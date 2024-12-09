# volatility3 tests
#

#
# IMPORTS
#

import argparse
import hashlib
import json
import ntpath
import os
import pytest
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Tuple, Type, Union
from volatility3.cli import volargparse
from volatility3.framework.configuration import requirements
from volatility3 import framework
from volatility3.framework import (
  automagic,
  contexts,
  plugins,
  interfaces,
)
import volatility3.plugins

sys.path.append("/home/runner/work/volatility3/volatility3")


#
# HELPER FUNCTIONS
#


def runvol(args, volatility, python):
    volpy = volatility
    python_cmd = python

    cmd = [python_cmd, volpy] + args
    print(" ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    print("stdout:")
    sys.stdout.write(str(stdout))
    print("")
    print("stderr:")
    sys.stdout.write(str(stderr))
    print("")

    return p.returncode, stdout, stderr


def runvol_plugin(plugin, img, volatility, python, pluginargs=[], globalargs=[]):
    args = (
        globalargs
        + [
            "--single-location",
            img,
            "-q",
            plugin,
        ]
        + pluginargs
    )
    return runvol(args, volatility, python)
    

def populate_requirements_argparse(
    parser: Union[argparse.ArgumentParser, argparse._ArgumentGroup],
    configurable: Type[interfaces.configuration.ConfigurableInterface],
):
    """Adds the plugin's simple requirements to the provided parser.

    Args:
        parser: The parser to add the plugin's (simple) requirements to
        configurable: The plugin object to pull the requirements from
    """
    if not issubclass(configurable, interfaces.configuration.ConfigurableInterface):
        raise TypeError(
            f"Expected ConfigurableInterface type, not: {type(configurable)}"
        )

    # Construct an argparse group

    for requirement in configurable.get_requirements():
        additional: Dict[str, Any] = {}
        if not isinstance(
            requirement, interfaces.configuration.RequirementInterface
        ):
            raise TypeError(
                "Plugin contains requirements that are not RequirementInterfaces: {}".format(
                    configurable.__name__
                )
            )
        if isinstance(requirement, interfaces.configuration.SimpleTypeRequirement):
            additional["type"] = requirement.instance_type
            if isinstance(requirement, requirements.IntRequirement):
                additional["type"] = lambda x: int(x, 0)
            if isinstance(requirement, requirements.BooleanRequirement):
                additional["action"] = "store_true"
                if "type" in additional:
                    del additional["type"]
        elif isinstance(
            requirement,
            volatility3.framework.configuration.requirements.ListRequirement,
        ):
            # Allow a list of integers, specified with the convenient 0x hexadecimal format
            if requirement.element_type == int:
                additional["type"] = lambda x: int(x, 0)
            else:
                additional["type"] = requirement.element_type
            nargs = "*" if requirement.optional else "+"
            additional["nargs"] = nargs
        elif isinstance(
            requirement,
            volatility3.framework.configuration.requirements.ChoiceRequirement,
        ):
            additional["type"] = str
            additional["choices"] = requirement.choices
        else:
            continue
        parser.add_argument(
            "--" + requirement.name.replace("_", "-"),
            help=requirement.description,
            default=requirement.default,
            dest=requirement.name,
            required=not requirement.optional,
            **additional,
        )


class Plugin:
  def __init__(self, os, directories, file_name, class_name, full_name, inputs):
    self.os = os
    self.directories = directories
    self.file_name = file_name
    self.class_name = class_name
    self.full_name = full_name
    self.inputs = inputs

def sort_plugins(plugins):
  results = []
  
  for plugin in plugins:
    full_name = plugin
    count = plugin.count('.')
    if count == 1:
      p = Plugin("misc", "", plugin[:plugin.find('.')], plugin[plugin.find('.')+1:], full_name, [])
      results.append(p)
    elif count == 2:
      os = plugin[:plugin.find('.')]
      file_name = plugin[plugin.find('.')+1:plugin.rfind('.')]
      class_name = plugin[plugin.rfind('.')+1:]
      p = Plugin(os, "", file_name, class_name, full_name, [])
      results.append(p)
    elif count == 3:
      os = plugin[:plugin.find('.')]
      class_name = plugin[plugin.rfind('.')+1:]
      plugin = plugin[:plugin.rfind('.')]
      file_name = plugin[plugin.rfind('.')+1:]
      directories = plugin[plugin.find('.')+1:plugin.rfind('.')]
      p = Plugin(os, directories, file_name, class_name, full_name, [])
      results.append(p)
    else:
      print("big problem")
        
  return results

def pytest_generate_tests(metafunc):
  # COPIED FROM VOLATILITY !!!
  parser = volargparse.HelpfulArgParser(
      add_help=False,
      description="An open-source memory forensics framework",
  )

  # Do the initialization
  ctx = contexts.Context()  # Construct a blank context
  failures = framework.import_files(
      volatility3.plugins, True
  )  # Will not log as console's default level is WARNING
  if failures:
      parser.epilog = (
          "The following plugins could not be loaded (use -vv to see why): "
          + ", ".join(sorted(failures))
      )
      print(parser.epilog)
  automagics = automagic.available(ctx)

  plugins = framework.list_plugins()
  all_plugins = list(plugins)

  seen_automagics = set()
  chosen_configurables_list = {}
  for amagic in automagics:
      if amagic in seen_automagics:
          continue
      seen_automagics.add(amagic)
      if isinstance(amagic, interfaces.configuration.ConfigurableInterface):
          populate_requirements_argparse(parser, amagic.__class__)

  subparser = parser.add_subparsers(
      title="Plugins",
      dest="plugin",
      description="For plugin specific options, run '{} <plugin> --help'".format(
          "volatility3"
      ),
      action=volargparse.HelpfulSubparserAction,
  )
  for plugin in sorted(plugins):
      plugin_parser = subparser.add_parser(
          plugin,
          help=plugins[plugin].__doc__,
          description=plugins[plugin].__doc__,
      )
      populate_requirements_argparse(plugin_parser, plugins[plugin])
      for action in plugin_parser._actions:
        if action.required and plugin in all_plugins:
          print(f"arguments required {action} for {plugin}")
          all_plugins.remove(plugin)


  all_plugins = sort_plugins(all_plugins)

  # These are the tests to skip; they have a return code != 0
  skip_tests = ['windows_shimcachemem', 'windows_kpcrs', 'windows_debugregisters', 'windows_virtmap', 'windows_vadyarascan', 'windows_netscan',
    'windows_passphrase', 'windows_scheduledtasks', 'windows_netstat', 'windows_crashinfo', 'linux_ebpf', 'linux_files', 'linux_capabilities',
    'linux_pidhashtable', 'linux_kthreads', 'linux_pstree', 'linux_vmayarascan', 'test_windows_hashdump', 'test_windows_lsadump', 'test_windows_cachedump']

  needs_test = []
  have_test = []
  for plugin in all_plugins:
    for test in skip_tests:
      if plugin.class_name.lower() in test and plugin.os in test:
        have_test.append(plugin)
        break
    if plugin not in have_test:
      needs_test.append(plugin)

  volatility='vol.py'
  python='python3'
  parameters = []
  for plugin in needs_test:
    parameters.append(f"test_{plugin.full_name}")
  
  metafunc.parametrize('plugin', parameters)

def test_vol_plugin(plugin, image, volatility, python):
  # tests are written as described in the assumptions
    rc, out, err = runvol_plugin(plugin[plugin.find("_")+1:], image, volatility, python)
    assert rc == 0


