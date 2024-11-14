# volatility3 tests
#

#
# IMPORTS
#

import os
import re
import subprocess
import sys
import shutil
import tempfile
import hashlib
import ntpath
import json

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
    

def test_misc_timeliner(image, volatility, python):
	rc, out, err = runvol_plugin("misc.timeliner.Timeliner", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_info(image, volatility, python):
	rc, out, err = runvol_plugin("windows.info.Info", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_poolscanner(image, volatility, python):
	rc, out, err = runvol_plugin("windows.poolscanner.PoolScanner", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_bigpools(image, volatility, python):
	rc, out, err = runvol_plugin("windows.bigpools.BigPools", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_hivescan(image, volatility, python):
	rc, out, err = runvol_plugin("windows.hivescan.HiveScan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_printkey(image, volatility, python):
	rc, out, err = runvol_plugin("windows.printkey.PrintKey", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_certificates(image, volatility, python):
	rc, out, err = runvol_plugin("windows.certificates.Certificates", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_misc_yarascan(image, volatility, python):
	rc, out, err = runvol_plugin("misc.yarascan.YaraScan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_misc_layerwriter(image, volatility, python):
	rc, out, err = runvol_plugin("misc.layerwriter.LayerWriter", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_misc_banners(image, volatility, python):
	rc, out, err = runvol_plugin("misc.banners.Banners", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_misc_isfinfo(image, volatility, python):
	rc, out, err = runvol_plugin("misc.isfinfo.IsfInfo", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_misc_configwriter(image, volatility, python):
	rc, out, err = runvol_plugin("misc.configwriter.ConfigWriter", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_misc_frameworkinfo(image, volatility, python):
	rc, out, err = runvol_plugin("misc.frameworkinfo.FrameworkInfo", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_misc_vmscan(image, volatility, python):
	rc, out, err = runvol_plugin("misc.vmscan.Vmscan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_mac_kauth_scopes(image, volatility, python):
	rc, out, err = runvol_plugin("mac.kauth_scopes.Kauth_scopes", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_mac_kauth_listeners(image, volatility, python):
	rc, out, err = runvol_plugin("mac.kauth_listeners.Kauth_listeners", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_mac_dmesg(image, volatility, python):
	rc, out, err = runvol_plugin("mac.dmesg.Dmesg", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_mac_bash(image, volatility, python):
	rc, out, err = runvol_plugin("mac.bash.Bash", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_mac_pstree(image, volatility, python):
	rc, out, err = runvol_plugin("mac.pstree.PsTree", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_mac_list_files(image, volatility, python):
	rc, out, err = runvol_plugin("mac.list_files.List_Files", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_mac_kevents(image, volatility, python):
	rc, out, err = runvol_plugin("mac.kevents.Kevents", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_mac_vfsevents(image, volatility, python):
	rc, out, err = runvol_plugin("mac.vfsevents.VFSevents", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_psscan(image, volatility, python):
	rc, out, err = runvol_plugin("linux.psscan.PsScan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_elfs(image, volatility, python):
	rc, out, err = runvol_plugin("linux.elfs.Elfs", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_psaux(image, volatility, python):
	rc, out, err = runvol_plugin("linux.psaux.PsAux", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_kthreads(image, volatility, python):
	rc, out, err = runvol_plugin("linux.kthreads.Kthreads", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_vmayarascan(image, volatility, python):
	rc, out, err = runvol_plugin("linux.vmayarascan.VmaYaraScan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_ptrace(image, volatility, python):
	rc, out, err = runvol_plugin("linux.ptrace.Ptrace", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_envars(image, volatility, python):
	rc, out, err = runvol_plugin("linux.envars.Envars", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_boottime(image, volatility, python):
	rc, out, err = runvol_plugin("linux.boottime.Boottime", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_check_afinfo(image, volatility, python):
	rc, out, err = runvol_plugin("linux.check_afinfo.Check_afinfo", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_bash(image, volatility, python):
	rc, out, err = runvol_plugin("linux.bash.Bash", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_check_modules(image, volatility, python):
	rc, out, err = runvol_plugin("linux.check_modules.Check_modules", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_mountinfo(image, volatility, python):
	rc, out, err = runvol_plugin("linux.mountinfo.MountInfo", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_files(image, volatility, python):
	rc, out, err = runvol_plugin("linux.pagecache.Files", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_inodepages(image, volatility, python):
	rc, out, err = runvol_plugin("linux.pagecache.InodePages", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_check_creds(image, volatility, python):
	rc, out, err = runvol_plugin("linux.check_creds.Check_creds", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_iomem(image, volatility, python):
	rc, out, err = runvol_plugin("linux.iomem.IOMem", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_netfilter(image, volatility, python):
	rc, out, err = runvol_plugin("linux.netfilter.Netfilter", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_pidhashtable(image, volatility, python):
	rc, out, err = runvol_plugin("linux.pidhashtable.PIDHashTable", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_ebpf(image, volatility, python):
	rc, out, err = runvol_plugin("linux.ebpf.EBPF", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_hidden_modules(image, volatility, python):
	rc, out, err = runvol_plugin("linux.hidden_modules.Hidden_modules", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_capabilities(image, volatility, python):
	rc, out, err = runvol_plugin("linux.capabilities.Capabilities", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_pstree(image, volatility, python):
	rc, out, err = runvol_plugin("linux.pstree.PsTree", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_keyboard_notifiers(image, volatility, python):
	rc, out, err = runvol_plugin("linux.keyboard_notifiers.Keyboard_notifiers", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_kmsg(image, volatility, python):
	rc, out, err = runvol_plugin("linux.kmsg.Kmsg", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_librarylist(image, volatility, python):
	rc, out, err = runvol_plugin("linux.library_list.LibraryList", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_linux_malfind(image, volatility, python):
	rc, out, err = runvol_plugin("linux.malfind.Malfind", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_vadyarascan(image, volatility, python):
	rc, out, err = runvol_plugin("windows.vadyarascan.VadYaraScan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_svclist(image, volatility, python):
	rc, out, err = runvol_plugin("windows.svclist.SvcList", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_svcdiff(image, volatility, python):
	rc, out, err = runvol_plugin("windows.svcdiff.SvcDiff", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_hashdump(image, volatility, python):
	rc, out, err = runvol_plugin("windows.hashdump.Hashdump", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_unloadedmodules(image, volatility, python):
	rc, out, err = runvol_plugin("windows.unloadedmodules.UnloadedModules", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_iat(image, volatility, python):
	rc, out, err = runvol_plugin("windows.iat.IAT", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_vadinfo(image, volatility, python):
	rc, out, err = runvol_plugin("windows.vadinfo.VadInfo", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_skeleton_key_check(image, volatility, python):
	rc, out, err = runvol_plugin("windows.skeleton_key_check.Skeleton_Key_Check", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_virtmap(image, volatility, python):
	rc, out, err = runvol_plugin("windows.virtmap.VirtMap", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_modscan(image, volatility, python):
	rc, out, err = runvol_plugin("windows.modscan.ModScan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_pedump(image, volatility, python):
	rc, out, err = runvol_plugin("windows.pedump.PEDump", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_threads(image, volatility, python):
	rc, out, err = runvol_plugin("windows.threads.Threads", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_threads(image, volatility, python):
	rc, out, err = runvol_plugin("windows.orphan_kernel_threads.Threads", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_suspiciousthreads(image, volatility, python):
	rc, out, err = runvol_plugin("windows.suspicious_threads.SuspiciousThreads", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_sessions(image, volatility, python):
	rc, out, err = runvol_plugin("windows.sessions.Sessions", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_pesymbols(image, volatility, python):
	rc, out, err = runvol_plugin("windows.pe_symbols.PESymbols", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_unhooked_system_calls(image, volatility, python):
	rc, out, err = runvol_plugin("windows.unhooked_system_calls.unhooked_system_calls", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_lsadump(image, volatility, python):
	rc, out, err = runvol_plugin("windows.lsadump.Lsadump", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_cachedump(image, volatility, python):
	rc, out, err = runvol_plugin("windows.cachedump.Cachedump", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_debugregisters(image, volatility, python):
	rc, out, err = runvol_plugin("windows.debugregisters.DebugRegisters", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_scheduledtasks(image, volatility, python):
	rc, out, err = runvol_plugin("windows.scheduled_tasks.ScheduledTasks", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_symlinkscan(image, volatility, python):
	rc, out, err = runvol_plugin("windows.symlinkscan.SymlinkScan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_joblinks(image, volatility, python):
	rc, out, err = runvol_plugin("windows.joblinks.JobLinks", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_cmdline(image, volatility, python):
	rc, out, err = runvol_plugin("windows.cmdline.CmdLine", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_mftscan(image, volatility, python):
	rc, out, err = runvol_plugin("windows.mftscan.MFTScan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_ads(image, volatility, python):
	rc, out, err = runvol_plugin("windows.mftscan.ADS", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_memmap(image, volatility, python):
	rc, out, err = runvol_plugin("windows.memmap.Memmap", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_shimcachemem(image, volatility, python):
	rc, out, err = runvol_plugin("windows.shimcachemem.ShimcacheMem", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_ssdt(image, volatility, python):
	rc, out, err = runvol_plugin("windows.ssdt.SSDT", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_driverscan(image, volatility, python):
	rc, out, err = runvol_plugin("windows.driverscan.DriverScan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_drivermodule(image, volatility, python):
	rc, out, err = runvol_plugin("windows.drivermodule.DriverModule", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_kpcrs(image, volatility, python):
	rc, out, err = runvol_plugin("windows.kpcrs.KPCRs", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_verinfo(image, volatility, python):
	rc, out, err = runvol_plugin("windows.verinfo.VerInfo", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_netscan(image, volatility, python):
	rc, out, err = runvol_plugin("windows.netscan.NetScan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_processghosting(image, volatility, python):
	rc, out, err = runvol_plugin("windows.processghosting.ProcessGhosting", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_filescan(image, volatility, python):
	rc, out, err = runvol_plugin("windows.filescan.FileScan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_ldrmodules(image, volatility, python):
	rc, out, err = runvol_plugin("windows.ldrmodules.LdrModules", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_netstat(image, volatility, python):
	rc, out, err = runvol_plugin("windows.netstat.NetStat", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_getservicesids(image, volatility, python):
	rc, out, err = runvol_plugin("windows.getservicesids.GetServiceSIDs", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_pstree(image, volatility, python):
	rc, out, err = runvol_plugin("windows.pstree.PsTree", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_mutantscan(image, volatility, python):
	rc, out, err = runvol_plugin("windows.mutantscan.MutantScan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_driverirp(image, volatility, python):
	rc, out, err = runvol_plugin("windows.driverirp.DriverIrp", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_consoles(image, volatility, python):
	rc, out, err = runvol_plugin("windows.consoles.Consoles", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_cmdscan(image, volatility, python):
	rc, out, err = runvol_plugin("windows.cmdscan.CmdScan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_psxview(image, volatility, python):
	rc, out, err = runvol_plugin("windows.psxview.PsXView", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_privs(image, volatility, python):
	rc, out, err = runvol_plugin("windows.privileges.Privs", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_timers(image, volatility, python):
	rc, out, err = runvol_plugin("windows.timers.Timers", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_hollowprocesses(image, volatility, python):
	rc, out, err = runvol_plugin("windows.hollowprocesses.HollowProcesses", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_amcache(image, volatility, python):
	rc, out, err = runvol_plugin("windows.amcache.Amcache", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_crashinfo(image, volatility, python):
	rc, out, err = runvol_plugin("windows.crashinfo.Crashinfo", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_strings(image, volatility, python):
	rc, out, err = runvol_plugin("windows.strings.Strings", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_mbrscan(image, volatility, python):
	rc, out, err = runvol_plugin("windows.mbrscan.MBRScan", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_malfind(image, volatility, python):
	rc, out, err = runvol_plugin("windows.malfind.Malfind", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_passphrase(image, volatility, python):
	rc, out, err = runvol_plugin("windows.truecrypt.Passphrase", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_getcellroutine(image, volatility, python):
	rc, out, err = runvol_plugin("windows.getcellroutine.GetCellRoutine", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

def test_windows_userassist(image, volatility, python):
	rc, out, err = runvol_plugin("windows.userassist.UserAssist", image, volatility, python)
	if rc != 0 and "the following arguments are required" not in err: 
		print(err)
	assert rc == 0

