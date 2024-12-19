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

  return plugins

def pytest_generate_tests(metafunc):

  all_plugins = get_plugins_from_vol3()

  parameters = []
  ids = []
  for plugin in all_plugins:
    parameters.append(all_plugins[plugin])
    ids.append(plugin)

  
  metafunc.parametrize('plugin', parameters, ids=ids)


def test_vol_plugin(plugin, image):
  # tests are written as described in the assumptions
  ctx = contexts.Context()  # Construct a blank context
  constructed = None
  ctx.config["automagic.LayerStacker.single_location"] = requirements.URIRequirement.location_from_file(image)

  progress_callback = PrintedProgress()

  automagics = automagic.available(ctx)
  base_config_path = "plugins"
  constructed = plugins.construct_plugin(
      ctx,
      automagics,
      plugin,
      base_config_path,
      progress_callback,
      CommandLine().file_handler_class_factory(),
  )

  # Construct and run the plugin
  if constructed:
      grid = constructed.run()
      print(grid)
