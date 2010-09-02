#!/usr/bin/python

'''
FuzzDiff
Written by: Dan Rosenberg and Will Dormann

This is a simple tool designed to help out with crash analysis during fuzz
testing.  It selectively "un-fuzzes" portions of a fuzzed file that is known to
cause a crash, re-launches the targeted application, and sees if it still
crashes.  Eventually, this will yield a file that still causes the crash, but
contains a minimum set of changes from the original un-fuzzed file.

Copyright (C) 2010 Virtual Security Research, LLC. - All rights reserved

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program.  If not, see <http://www.gnu.org/licenses/>.

'''

import sys
import os
import random
import shutil
import subprocess
import time
import shlex
import signal

logfile = open('stats.log', 'a')

# Probability a fuzzed byte will be reverted
# The higher this value, the more aggressive the testcase minimization will be
REVERTCHANCE = .7

# Number of iterations at each threshold
# The higher this value, the more attempts this script will try to minimize
ITER = 20

# Number of bytes different before switching to manual iteration
# The higher this value, the greater chance of a definitive minimization,
# at the cost of speed
MANUALCUTOFF = 10

# Different applications return different error codes on crash
# Shell scripts and some applications return non-standard exit codes when they are handled
CRASHEXITCODES = [-11, -8, -6, -4, -1, 1, 129, 132, 134, 136, 139 ]

# Seconds to wait before killing target program
WAIT = 1


def unfuzz(seed, fuzz, out):
	global manual_iteration
	seedstat = os.stat(seed)
	fuzzstat = os.stat(fuzz)

	if(seedstat.st_size != fuzzstat.st_size):
		print '[*] Files are not the same size.'
		term(-1)
	
	try:
		seedfd = open(seed, 'rb')
		fuzzfd = open(fuzz, 'rb')
		outfd = open(out, 'wb')
	except:
		print '[*] Error opening file - bad arguments'
		term(-1)

	diff = 0
	unchanged = 0
		
	# Randomly (per-byte) revert fuzzed bytes to seed values
	while(1):
		c = seedfd.read(1)
		if not c: break
		d = fuzzfd.read(1)

		# If there's a diff...
		if(c != d):
			diff += 1
			if(lastunchanged > MANUALCUTOFF or minimizing==0):
				# With some probability, revert it
				if(random.random() <= discardchance):
					outfd.write(c)				
				else:
					unchanged += 1
					outfd.write(d)
			else:
				# Random doesn't make sense anymore.  Just enumerate last variants
				# each iteration will have one fewer bytes from the fuzzed file
				if(manual_iteration == diff):
					print 'Reverting byte ' + str(diff) + ' of ' + str(lastunchanged)
					# Use the seed byte
					outfd.write(c)
				else:
					# Use the fuzzed byte
					unchanged += 1
					outfd.write(d)
		else:
			outfd.write(c)
	if(lastunchanged<=MANUALCUTOFF):
		# Increment current different byte counter
		manual_iteration += 1
	
	return (diff, unchanged)

def term(ret):
	print '[*] Terminating...'
	try:
		os.remove(TMPFILE)
	finally:
		sys.exit(ret)
		
def handler(signum, frame):
	print 'Killing process...'
	p.kill()
	

#######################
# Program entry point #
#######################

if(len(sys.argv) < 6):
	print '[*] Usage: fuzzdiff [seed] [program] [preargs] [fuzzed] [postargs]\n' + \
		'Use - for argument placeholder\n'
	sys.exit(-1)

program = sys.argv[2]
preargs = sys.argv[3]
fuzzed = sys.argv[4]
postargs = sys.argv[5]
seed = sys.argv[1]
best = sys.argv[4] + '.minimal' 

if(preargs=='-'):
	preargs=''
if(postargs=='-'):
	postargs=''

try:
	shutil.copy(fuzzed, best)
except:
	print '[*] Error opening file - bad fuzzfile argument'
	term(-1)

logfile.write('\nMinimizing ' + fuzzed + '\n')

null = open('/dev/null', 'rw')

# Temporary output
TMPFILE = '/tmp/tmp-' + str(seed)

attempts = ITER
totaliterations = 0
lastunchanged = MANUALCUTOFF + 1
manual_iteration = 0
minimizing = 0
different_bytes = 0
discardchance = REVERTCHANCE

# Check how the program crashes
print '[*] Checking exit code for ' + str(fuzzed) + '...'
command_line = program + ' ' + preargs + ' ' + fuzzed + ' ' + postargs
args = shlex.split(command_line)
try:
	p = subprocess.Popen(args, stdout=null, stderr=null)
except:
	print '[*] Error running program'
	term(-1)

# Set up timeout alarm
signal.signal(signal.SIGALRM, handler)
# Give extra time for the first invocation of the application
signal.alarm(WAIT*2)
p.wait()
signal.alarm(0)

# If it segfaulted, keep the changes
print 'Checking status: ' + str(p.poll())
testexit = p.poll()
if (testexit in CRASHEXITCODES):
	print '[*] Found crashing exit code: ' + str(testexit)
else:
	print '[*] Unmatched exit code. Did it crash?  Timeout too short?'
	term(-1)
	
# If the program hasn't terminated, kill it
if(p.returncode == None):
	p.kill()

print 'Starting minimization with ' + str(ITER) + ' iterations with ' + \
	str(discardchance*100) + '% chance of using byte values from seed file'

# Main loop
while (discardchance > 0.02):
	while (attempts > 0):
		
		(diff, unchanged) = unfuzz(seed, best, TMPFILE)
		totaliterations = totaliterations + 1
		# Only bother if we actually reduced the number of diffs
		if(unchanged < diff):
			command_line = program + ' ' + TMPFILE + ' ' + postargs
			args = shlex.split(command_line)
	
			# Test if the result still crashes the target
			try:
				p = subprocess.Popen(args, stdout=null, stderr=null)
			except:
				print '[*] Error running program'
				term(-1)
	
			# Set timeout alarm
			signal.alarm(WAIT)
			p.wait()
			signal.alarm(0)	
			
			testexit = p.poll()
			# If it segfaulted, keep the changes
			print 'Checking status: ' + str(testexit)
			
			if (testexit in CRASHEXITCODES):
				shutil.copy(TMPFILE, best)
				print '[*] Reduced diffs from', diff, 'to', unchanged
				minimizing = 1
				lastunchanged = unchanged
				print 'Resetting attempt counter to ' + str(ITER)
				attempts = ITER
				if(unchanged <= MANUALCUTOFF and unchanged > 1):
					manual_iteration=1 # begin manual iteration 
					break
				if(unchanged == 1):
					print 'Made it to one byte difference!  Stopping'
					attempts = 0
					discardchance = 0
					break			
	
			# If the program hasn't terminated, kill it
			elif(testexit == None):
				print 'Killing process...'
				p.kill()
			attempts = attempts - 1
			print 'Attempts left: ' + str(attempts)
		if(manual_iteration > lastunchanged):
			print '[*] Cannot minimize any further!'
			attempts = 0
			discardchance = 0
			break
	if(manual_iteration==0):
		discardchance = discardchance - .1
		print 'New percent chance of discarding changed bytes: ' + str(discardchance)
		attempts = ITER
	
if(minimizing):
	# Use count from last time the number of different bytes changed
	different_bytes = lastunchanged
else:
	# Use the entire number of different bytes
	different_bytes = diff
	logfile.write('Testcase unable to be minimized.\nPerhaps try higher ITER ' +  
		'and lower discardchance values?')
	print '[*] Testcase unable to be minimized.'
print '[*] Minimally different file created. Bytes different: ' + str(different_bytes)
print 'Total iterations: ' + str(totaliterations)
logfile.write(str(different_bytes) + ' bytes different after ' + str(totaliterations) + ' iterations\n' + 
	'revert chance: ' + str(REVERTCHANCE) + ' iterations: ' + str(ITER) + 
	' manual threshold: ' + str(MANUALCUTOFF) + '\n\n')
logfile.close()
term(1)
