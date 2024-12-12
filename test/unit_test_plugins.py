# volatility3 tests
#

#
# IMPORTS
#

import argparse
import copy
import os
import pytest
import subprocess
import sys
from volatility3.cli import volargparse, CommandLine, PrintedProgress
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

def get_plugins_from_vol3():
  # COPIED FROM VOLATILITY !!!

  # Do the initialization
  ctx = contexts.Context()  # Construct a blank context
  parser = volargparse.HelpfulArgParser(
      add_help=False,
      description="An open-source memory forensics framework",
  )

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
        if action.required and plugin in plugins:
          print(f"arguments required {action} for {plugin}")
          del plugins[plugin]

  return plugins, ctx

def pytest_generate_tests(metafunc):

  all_plugins, ctx = get_plugins_from_vol3()

  # These are the tests to skip; they have a return code != 0
  skip_tests = ['windows.virtmap.VirtMap', 'windows.scheduled_tasks.ScheduledTasks', 'windows.crashinfo.Crashinfo', 'linux.hidden_modules.Hidden_modules', 'linux.kmsg.Kmsg']

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
  ids = []
  for plugin in needs_test:
    parameters.append((all_plugins[plugin], copy.deepcopy(ctx)))
    ids.append(plugin)
  
  metafunc.parametrize('plugin, context', parameters, ids=ids)

def test_vol_plugin(plugin, context, image, volatility, python):
  # tests are written as described in the assumptions
  constructed = None
  context.config["automagic.LayerStacker.single_location"] = requirements.URIRequirement.location_from_file(image)
  try:
      progress_callback = PrintedProgress()

      automagics = automagic.available(context)
      base_config_path = "plugins"
      constructed = plugins.construct_plugin(
          context,
          automagics,
          plugin,
          base_config_path,
          progress_callback,
          CommandLine().file_handler_class_factory(),
      )

  except Exception as e:
          print(
          f"Unable to validate the plugin requirements: {e}\n",
      )
          assert True == False

  try:
      # Construct and run the plugin
      if constructed:
          grid = constructed.run()
          print(grid)
  except Exception as e:
      print('exception', e)
      assert 1 == 2
