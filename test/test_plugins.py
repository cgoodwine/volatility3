# volatility3 tests
#

#
# IMPORTS
#

import argparse
import os
import pytest
import subprocess
import sys
from volatility3.cli import volargparse, CommandLine
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
    

def get_plugins_from_vol3():
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
          CommandLine().populate_requirements_argparse(parser, amagic.__class__)

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
      CommandLine().populate_requirements_argparse(plugin_parser, plugins[plugin])
      for action in plugin_parser._actions:
        if action.required and plugin in all_plugins:
          print(f"arguments required {action} for {plugin}")
          all_plugins.remove(plugin)

  return all_plugins

def pytest_generate_tests(metafunc):

  all_plugins = get_plugins_from_vol3()

  # These are the tests to skip; they have a return code != 0
  skip_tests = ['windows.shimcachemem', 'windows.kpcrs', 'windows.debugregisters', 'windows.virtmap', 'windows.vadyarascan', 'windows.netscan',
    'windows.truecrypt', 'windows.scheduledtasks', 'windows.netstat', 'windows.crashinfo', 'linux.ebpf', 'linux.files', 'linux.capabilities',
    'linux.pidhashtable', 'linux.kthreads', 'linux.pstree', 'linux.vmayarascan', 'windows.hashdump', 'windows.lsadump', 'windows.cachedump', 'windows.scheduled_tasks',
    'linux.kmsg', 'linux.hidden_modules']

  needs_test = []
  have_test = []
  for plugin in all_plugins:
    for test in skip_tests:
      if test in plugin:
        have_test.append(plugin)
        break
    if plugin not in have_test:
      needs_test.append(plugin)

  parameters = []
  for plugin in needs_test:
    parameters.append(f"test_{plugin}")
  
  metafunc.parametrize('plugin', parameters)


def test_vol_plugin(plugin, image, volatility, python):
  # tests are written as described in the assumptions
    rc, out, err = runvol_plugin(plugin[plugin.find("_")+1:], image, volatility, python)
    assert rc == 0
