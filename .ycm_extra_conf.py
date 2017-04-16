import os
import ycm_core
import logging
import subprocess
import re

vimvs_exe = ""

def Vimvs_getycm( filename ):
	global vimvs_exe
	startupinfo = subprocess.STARTUPINFO()
	startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
	p = subprocess.Popen([vimvs_exe, '-getycm=' + filename], stdout=subprocess.PIPE, startupinfo=startupinfo)
	out,err = p.communicate()
	if p.returncode>0:
		raise Exception("VIMVS: getycm failed")
	strings = re.search("^\s*YCM_CMD:(.*)", out, flags=re.MULTILINE)
	if strings is None:
		raise Exception("VIMVS: error parsing getycm output. Could not find YCM_CMD line.")

	res = []
	cmds = strings.group(1).split("|")
	for cmd in cmds:
		if cmd.strip()!="":
			res.append(cmd)
	return res

def FlagsForFile( filename, **kwargs ):
	global vimvs_exe
	if not (kwargs and 'client_data' in kwargs):
		raise Exception("VIMVS: client_data not found in kwargs")
	client_data = kwargs['client_data']
	if not (client_data and 'g:vimvs_exe' in client_data):
		raise Exception("VIMVS: g:vimvs_exe not present in client_data")
	vimvs_exe = client_data['g:vimvs_exe']
	cmd = Vimvs_getycm( filename )
	return {
		'flags' : cmd,
		'do_cache' : True
	}

