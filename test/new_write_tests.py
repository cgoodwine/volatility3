# ASSUMPTIONS: 
#   1. all existing plugin tests are contained in test_volatility.py 
#   2. all existing plugin tests are functions named 'test_[windows OR mac OR linux OR misc]_FILENAME'
#     2.1 ex: test_windows_psslist means it tests all classes in the volatility3/framework/plugins/windows/psslist.py file
#   3. all plugins can be found calling framework.list_plugins()
#   4. all plugins are named [windows OR mac OR linux OR FILENAME (for misc)].FILENAME+.CLASSNAME (except for the misc plugins) (FILENAME+ means there can be multiple directories
#      between [windows OR mac OR linux] and the classname; the only one that actually exists as of now is windows/registry/)
#     4.1 ex: windows.mftscan.MFTScan or windows.mftscan.ADS means that volatility3/framework/plugins/windows has a file named 'mftscan.py' and that has (at least) two classes named MFTScan and ADS
#     4.2 ex: banners.Banners means that volatility3/framework/plugins/ has a file named 'banners.py' and that has (at least) one class named Banners
#     4.3 ex: windows.registry.hivelist.HiveList means that volatility3/framework/plugins/windows/registry/hivelist has (at least) one class named HiveList
#       4.3.1 ex: in cases like this, the test would be named after the LAST filename in the list (hivelist, not registry)
#   5. all plugins can be found under volatility3/framework/plugins/[windows OR mac OR linux OR nothing for misc]
#     5.1: this needs to be updated; forgot that there was a volatility3/plugins/[windows OR mac OR linux] case; it does seem like the only one to actually use this case is windows (mac and linux
#          just have __init__.py in that folder but still should check it in case that changes
          


# Options for inputs to plugins:
#  1. no inputs
#  2. one input: either interfaces.plugin.PluginInterface OR plugins.PluginInterface
#    2a. one input: unique (?? maybe works maybe not; seems ok for some of them but still fine-tuning)
#  3. two inputs: (either interfaces.plugin.PluginInterface OR plugins.PluginInterface) combined with (timeliner.TimelinerInterface)

import os
import sys
import re
import subprocess
sys.path.append("/home/runner/work/volatility3/volatility3")

from volatility3 import framework
import volatility3.plugins
from volatility3.framework import (
  automagic,
  contexts,
  plugins,
)

def runvol(args, volatility, python, plugin):
    volpy = volatility
    python_cmd = python

    cmd = [python_cmd, volpy] + args + ['--help']
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    output = str(stdout)
    output = output.replace(r'\n', '\n')
    usage = output.splitlines()[1] + '\n'
    if len(output.splitlines()[2]) > 0:
      usage = usage.strip("\n")
      usage = usage + output.splitlines()[2]
    while "[" in usage:
      usage = re.sub(r"\[[a-zA-Z\s\.\-_]*\]|\[[a-zA-Z\s\._]*\[[a-zA-Z\s\._]*\][a-zA-Z\s\._]*\]", "", usage)
    if "--" in usage:
      print("arguments required:", " ".join(cmd) + " " + str(p.returncode))
    else: 
      write_vol_plugin(plugin, "test/test_volatility_plugins.py")
      print("wrote test for:", " ".join(cmd) + " " + str(p.returncode))


    return p.returncode


def runvol_plugin(plugin, img, volatility, python, full_plugin, pluginargs=[], globalargs=[]):
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

    return runvol(args, volatility, python, full_plugin)


def write_vol_plugin(plugin, file_name):
  # tests are written as described in the assumptions
  test_func = 'test_' + plugin.os + '_' + plugin.class_name.lower()
  parameters = 'image, volatility, python'
  with open(file_name, 'a') as f:
    f.write('def ' + test_func + '(' + parameters + '):\n')
    f.write('\trc, out, err = runvol_plugin(\"' + plugin.os + '.' + plugin.file_name + '.' + plugin.class_name + '\", image, volatility, python)\n')
    f.write('\tassert rc == 0\n\n')


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


def get_inputs(plugins):
  relative_path = "volatility3/framework/plugins/"
  for plugin in plugins:
    # build path
    full_path = relative_path
    if plugin.os != "misc":
      full_path += (plugin.os + "/")
    if plugin.directories != "":
      continue # SKIP NESTED DIRECTORIES FOR NOW
    full_path += (plugin.file_name + '.py')
    
    try:
      with open(full_path, 'r') as file:
        # find the classes
        for line in file:
          if "class " + plugin.class_name + "(" in line:
            inputs = line[line.find('(')+1:line.find(')')].split(', ')
            for i in inputs:
              plugin.inputs.append(i)
    except Exception:
      print("couldn't find path:", full_path)
      del plugins[plugins.index(plugin)]


def find_existing_tests(file_name):
  test_names = []

  with open("test/" + file_name, 'r') as f:
    for line in f:
      if 'def' in line and 'test' in line:
        func_name = line[line.find('test'):line.find('(')]
        plugin = Plugin(func_name[func_name.find('_')+1:func_name.find('_', func_name.find('_')+1)], '', '', '', func_name[func_name.find('_', func_name.find('_')+1)+1:], [])
        test_names.append(plugin)
        print("def and test in line", line, "with func name", func_name)
        
  return test_names

def main():

  # COPIED FROM VOLATILITY !!!
  # Do the initialization
  ctx = contexts.Context()  # Construct a blank context
  failures = framework.import_files(
      volatility3.plugins, True
  )  # Will not log as console's default level is WARNING
  if failures:
      epilog = (
          "The following plugins could not be loaded (use -vv to see why): "
          + ", ".join(sorted(failures))
      )
      print(epilog)
  automagics = automagic.available(ctx)

  plugins = framework.list_plugins()

  all_plugins = sort_plugins(plugins)

  get_inputs(all_plugins)
  found_tests = find_existing_tests('test_volatility.py')

  extra_weird_count = 0
  kinda_weird_count = 0
  normal_count = 0
  needs_test = []
  have_test = []
  for plugin in all_plugins:
    for test in found_tests:
      if plugin.class_name.lower() in test.full_name and plugin.os == test.os:
        have_test.append(plugin)
        break
    if plugin not in have_test:
      needs_test.append(plugin)

  volatility='vol.py'
  image=sys.argv[1]
  os_type=sys.argv[2]
  python='python3'
  need_parameters = []
  failed = []
  for plugin in needs_test:
    return_code = -1
    if plugin.os != os_type:
      continue
    if len(plugin.inputs) == 1:
        return_code = runvol_plugin(plugin.os + '.' + plugin.file_name + '.' + plugin.class_name, image, volatility, python, plugin)
    if len(plugin.inputs) == 2:
        return_code = runvol_plugin(plugin.os + '.' + plugin.file_name + '.' + plugin.class_name, image, volatility, python, plugin)
    if return_code != -1:
      if return_code == 1:
        failed.append(plugin)
      elif return_code == 2:
        need_parameters.append(plugin)
      elif return_code != 0:
        print("weird return code {return_code} for plugin {plugin.class_name}")
    
if __name__ == '__main__':
  main()
