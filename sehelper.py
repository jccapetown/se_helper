#!/usr/bin/python

#Import Section
import os,sys,glob, shutil
import subprocess

#Prerequisite folders
pol_dir = 'policies'
if not os.path.exists(pol_dir):
    os.makedirs(pol_dir)

custompol_dir = 'custompolicies'
if not os.path.exists(custompol_dir):
    os.makedirs(custompol_dir)

#public declarations and classes
audit_entry_classes = []
process_list = set()

class class_auditentry:
	originalentry = ''
	exception = False
	PID = ''
	Process = ''
	Action = ''
	Source_Context = ''
	Dest_Context = ''

	def __init__(self, auditentry):
		self.originalentry = auditentry
		
		self.setup()

	def setup(self):
		try:

			itemparts = self.originalentry.split(' ')
			for ix,item in enumerate(itemparts):
				#print item
				if 'pid' in item.lower():
					self.PID = itemparts[ix]

				if 'comm' in item.lower():
					self.Process = itemparts[ix].replace('comm=','').replace('"','')

				self.Action = itemparts[4]


				if 'scontext' in item.lower():
					self.Source_Context = itemparts[ix]
		
				
				if 'tcontext' in item.lower():
					self.Dest_Context = itemparts[ix]
		except Exception, e:
			self.exception = True
			print "exception:: ", e.message 
			pass

def print_header():
	os.system('clear')
	print 'sehelper 0.1'
	print 'A tool to help manage SELinux'
	print 'Author:  Jacques Coetzee aka sabrewolf'
	print ''

def print_mainmenu():
	idnt = ' '*2	
	print "Troubleshooting"
	print "==============="
	print idnt,"T1.  Find and fix issues (BASIC)"
	print idnt,"T2.  Fix all issues automagically (ADVANCED)"	
	print idnt,"T3.  List current enforced modules"
	print idnt,"T4.  Remove an enforced module"
	print idnt,"T5.  Build and install selinux module from .te policy file (in custompolicies folder)"
	#print""
	print "Informational"
	print "============="
	print idnt,"I1.  Get SELinux running info"
	print idnt,"I2.  Set mode to Permissive (temporarily)"
	print idnt,"I3.  Set mode to Enforce (temporarily)"
	print idnt,"I4.  Get SELInux users"
	print idnt,"I5.  Get SELInux logins"
	print idnt,"I6.  Get SELInux ports"
	#print""
	print "Users"
	print "====="
	print idnt,"U1. Map a local user to a selinux user"
	print idnt,"U2. Remap a mapped local user to another selinux user"
	print idnt,"U3. Remove the mapping between user and selinux user."
	#print""
	print "Groups"
	print "======"
	print idnt,"G1. Map a local/domain group to a selinux user context. (all users in group adopt this context)"
	print idnt,"G2. Remap a local/domain group to another selinux user context. (all users in group adopt this context)"
	print idnt,"G3. Remove a local/domain group's selinux user context. (affects all users in this group)"
	#print""
	print "Ports"
	print "====="
	print idnt,"P1. Map an application port to an SELinux port type for access"
	print idnt,"P2. Remove an application port from an SELinux port type"
	print ""
	print "x = Exit"


#------------------- TROUBLE SHOOTING FUNCTIONS --------------------------#

#print "T1.  Find and fix issues (BASIC)"
def run_menu_T1():
	#Show list of applications/processes that dont work
	inputstr = ''

	while inputstr != 'x':
		selected_classes = []
		print_header()

		#print_header()
		print ""
		for item in audit_entry_classes:
			process_list.add(item.Process.lower())

		print "Current Applications with possible issues"
		print "========================================="
		for ix, name in enumerate(process_list):
			print str(ix+1) + ': ' + name

		print ""
		inputstr=raw_input('Application to investigate[name]: ')
		if inputstr in process_list:		
			for ix,item in enumerate(audit_entry_classes):
				if item.Process.lower() == inputstr.lower():
					selected_classes.append(item)
					print "*"*10
					print inputstr.upper()
					print ' '*2,'ProcessId: ', item.PID
					print ' '*2,'Process  : ', item.Process
					print ' '*2,'Action   : ', item.Action
					print ' '*2,'S Context: ', item.Source_Context
					print ' '*2,'T Context: ', item.Dest_Context
					print ' '*2,'Original : ', item.originalentry

	
			print ""
			print ""
			print "Options"
			print "======="
			print "1. Show policy to fix %s " % inputstr
			print "2. Create Policy Files for %s" % inputstr

			print ""
			option = raw_input('Option: ')
	
			if option == '1':
				cmd_1 = ['grep', 'AVC', '/var/log/audit/audit.log']	
				cmd_2 = ['grep' , 'comm="%s"' % inputstr]	
				cmd_3 = ['audit2allow']	
				p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
				p2 = subprocess.Popen(cmd_2, stdin = p1.stdout, stdout=subprocess.PIPE)
				p3 = subprocess.Popen(cmd_3, stdin = p2.stdout, stdout=subprocess.PIPE)
				out = p3.communicate()[0]
				print ""
				print"#======POLICY TO FIX %s====================#" % inputstr.upper()
				print out

			if option == '2':
				os.system('tar -zcvf %s/backup.tar %s/sehelper_pol*' % (pol_dir, pol_dir) )
				os.system('rm -rf %s/sehelper_pol*' % pol_dir)
				cmd_1 = ['grep', 'AVC', '/var/log/audit/audit.log']	
				cmd_2 = ['grep' , 'comm="%s"' % inputstr]	
				cmd_3 = ['audit2allow','-M', 'sehelper_pol_%s' % (inputstr)]	
				p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
				p2 = subprocess.Popen(cmd_2, stdin = p1.stdout, stdout=subprocess.PIPE)
				p3 = subprocess.Popen(cmd_3, stdin = p2.stdout, stdout=subprocess.PIPE)
				out = p3.communicate()[0]
			
				for strfile in glob.glob("sehelper_pol_*"):
					if os.path.isfile(strfile):
						shutil.move(strfile, pol_dir)

				yesno = raw_input("The policies have been created, would you like to import them into selinux for activation?[y/n]")
				if yesno == 'y':
					for policy in glob.glob('%s/sehelper_pol*.te' % pol_dir):
						polbinfile = policy.replace('.te','.pp')
						polmodfile = policy.replace('.te','.mod')
						#os.system('checkmodule -M -m -o %s %s' % (polmodfile, policy )
						#os.system('semodule_package -o %s -m %s'% (polbinfile, polmodfile )
						os.system('semodule -i %s' % polbinfile )
				
			raw_input('Press any key to continue')

				
#print "2.  Fix all issues automagically (ADVANCED)"	
def run_menu_T2():
	print_header()
	selected_classes = set()
	os.system('tar -zcvf %s/backup.tar %s/sehelper_pol*' % (pol_dir, pol_dir) )
	os.system('rm -rf %s/sehelper_pol*' % pol_dir)
	for item in audit_entry_classes:
		selected_classes.add(item)

	for item in selected_classes:
		print "*"*10
		print ' '*2,'ProcessId: ', item.PID
		print ' '*2,'Process  : ', item.Process
		print ' '*2,'Action   : ', item.Action
		print ' '*2,'S Context: ', item.Source_Context
		print ' '*2,'T Context: ', item.Dest_Context
		print ' '*2,'Original : ', item.originalentry

		cmd_1 = ['grep', 'AVC', '/var/log/audit/audit.log']	
		cmd_2 = ['grep' , 'comm="%s"' % item.Process]	
		cmd_3 = ['audit2allow','-M', 'sehelper_pol_%s' % (item.Process)]	
		p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
		p2 = subprocess.Popen(cmd_2, stdin = p1.stdout, stdout=subprocess.PIPE)
		p3 = subprocess.Popen(cmd_3, stdin = p2.stdout, stdout=subprocess.PIPE)
		out = p3.communicate()[0]
			
	for strfile in glob.glob("sehelper_pol_*"):
		if os.path.isfile(strfile):
			shutil.move(strfile, pol_dir)


	print ""
	print ""				
	yesno = raw_input("The policies have been created, would you like to import them into selinux for activation?[y/n]")
	if yesno == 'y':
		for policy in glob.glob('%s/sehelper_pol*.te' % pol_dir):
			polbinfile = policy.replace('.te','.pp')
			polmodfile = policy.replace('.te','.mod')
			#os.system('checkmodule -M -m -o %s %s' % (polmodfile, policy )
			#os.system('semodule_package -o %s -m %s'% (polbinfile, polmodfile )
			os.system('semodule -i %s' % polbinfile )


#print "T3.  List current enforced modules"
def run_menu_T3():
	print_header()
	cmd_1 = ['semodule', '-l']	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
	out = p1.communicate()[0]
	print out


#print "T4.  Remove an enforced module"
def run_menu_T4():
	choice = 'y'
	while choice == 'y':
		print_header()
		run_menu_T3()
		module = raw_input('What policy module would you like to remove: ')
		cmd_1 = ['semodule', '-r', module]	
		p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
		out = p1.communicate()[0]
		choice = raw_input('Remove Another?[y/n]: ')


#print idnt,"T5.  Build and install selinux module from .te policy file"
def run_menu_T5():
	choice = 'y'
	
	while choice == 'y':
		policies = []
		print_header()
		idnt = " "*2
		print "Found the follwing Policies"
		print "==========================="
		for ix,custompol in enumerate(glob.glob(custompol_dir + '/*.te')):
			print idnt,str(ix+1) + "." +  custompol[len(custompol_dir)+1:]
			policies.append( (ix+1, custompol) )
	
		print""
		module = raw_input('What policy module would you like to Install [1,2 etc]: ')
		try:
			for mod in policies:
				if mod[0] == int(module):		
					polfile = mod[1][0:-3]
					print polfile
					modpolfile = polfile + '.mod'
					pppolfile = polfile + '.pp'
					cmd_1 = ['checkmodule', '-M', '-m', '-o', modpolfile, mod[1] ]				
					p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
					cmd_1 = ['semodule_package', '-o', pppolfile,'-m', modpolfile ]				
					p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
					cmd_1 = ['semodule', '-i', pppolfile]				
					p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)

		except Exception, e:
			print e
			pass
		choice = raw_input('Build and Install Another?[y/n]: ')




#------------------ Information ---------------------------#


#print "5.  Get SELinux running info"
def run_menu_I1():
	print_header()
	cmd_1 = ['sestatus']	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
	out = p1.communicate()[0]
	print out
	

#print "6.  Set mode to Permissive (temporarily)"
def run_menu_I2():
	print_header()
	cmd_1 = ['setenforce', 'permissive']	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
	out = p1.communicate()[0]
	print "Mode change to permissive"
	

#print "7.  Set mode to Enforce (temporarily)"
def run_menu_I3():
	print_header()
	cmd_1 = ['setenforce', 'enforcing']	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
	out = p1.communicate()[0]
	print "Mode change to enforcing"

	
#print "8.  Get SELInux users"
def run_menu_I4():
	print_header()
	cmd_1 = ['semanage', 'user', '-l']	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
	out = p1.communicate()[0]
	print out 

	
#print "9.  Get SELInux logins"
def run_menu_I5():
	print_header()
	cmd_1 = ['semanage', 'login', '-l']	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
	out = p1.communicate()[0]
	print out 


#print idnt,"I6. Map an application port to an SELinux port type for access"
def run_menu_I6():
	print_header()
	cmd_1 = ['semanage', 'port', '-l']	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
	out = p1.communicate()[0]
	print out



#--------------------- Users ----------------#

#print "10. Map a local user to a selinux user"
def run_menu_U1():
	run_menu_I4()
	usercontext = raw_input('User context required: ')
	username = raw_input('For which username: ')
	cmd_1 = ['semanage', 'login', '-a', '-s', usercontext, username]	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
	out = p1.communicate()[0]
	print out 


#print "10. Map a local user to a selinux user"
def run_menu_U2():
	run_menu_I4()
	usercontext = raw_input('User context required: ')
	username = raw_input('For which username: ')
	cmd_1 = ['semanage', 'login', '-m', '-s', usercontext, username]	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
	out = p1.communicate()[0]


#print "12. Remove the mapping between user and selinux user."
def run_menu_U3():
	run_menu_I5()
	username = raw_input('For which username: ')
	cmd_1 = ['semanage', 'login', '-d', username]	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
	out = p1.communicate()[0]




#----------------- GROUPS ---------------------#

#print "13 Map a local or domain group to a selinux user context. (all users adopt this context)"
def run_menu_G1():
	run_menu_I4()
	usercontext = raw_input('User context required: ')
	groupname = raw_input('For which domain/localgroup: ')
	cmd_1 = ['semanage', 'login', '-a', '-s', usercontext, '%' + groupname]	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
	out = p1.communicate()[0]

#print "14. Remap a local/domain group to another selinux user context. (all users in group adopt this context)"
def run_menu_G2():
	run_menu_I4()
	usercontext = raw_input('User context required: ')
	groupname = raw_input('For which domain/localgroup: ')
	cmd_1 = ['semanage', 'login', '-m', '-s', usercontext, '%' + groupname]	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
	out = p1.communicate()[0]


#print "G3. Remopve a local/domain group's selinux user context. (affects all users in this group)"
def run_menu_G3():
	run_menu_I5()
	groupname = raw_input('For which domain/localgroup: ')
	cmd_1 = ['semanage', 'login', '-d', '%' + groupname]	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)


#-------------------- PORTS -------------------------#

#print "P1. Remopve a local/domain group's selinux user context. (affects all users in this group)"
def run_menu_P1():
	print_header()
	proto = raw_input('Protocol [udp,tcp]: ')
	run_menu_I6()
	port_type = raw_input('Port type: ')
	portnum = raw_input('Port Number: ')
	cmd_1 = ['semanage', 'port', '-a', '-p', proto, '-t', port_type, portnum]	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
	out = p1.communicate()[0]
	print out

#print idnt,"P2. Remove an application port from an SELinux port type"
def run_menu_P2():
	print_header()
	proto = raw_input('Protocol [udp,tcp]: ')
	run_menu_I6()
	port_type = raw_input('Port type: ')
	portnum = raw_input('Port Number: ')
	cmd_1 = ['semanage', 'port', '-d', '-p', proto, '-t', port_type, portnum]	
	p1 = subprocess.Popen(cmd_1, stdout = subprocess.PIPE)
	out = p1.communicate()[0]
	print out


#MAIN APPLICATION ENTRY

#Clear the Screen before we get started
os.system('clear')

euid = os.geteuid()
if euid != 0:
    print "Script not started as root. Running sudo.."
    args = ['sudo', sys.executable] + sys.argv + [os.environ]
    # the next line replaces the currently-running process with the sudo
    os.execlpe('sudo', *args)

#print_header()


#Collect some common issues
print "Collecting common issues..."
command = ['grep', 'AVC', '/var/log/audit/audit.log']
p = subprocess.Popen(command, stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE)
out, err = p.communicate()
auditlist = out.split('\n')

#print 'Parsing entries...'
#Parse all items in the audit list
for ix, item in enumerate(auditlist):
	try:
		if item.strip() == '':
			continue
		auditentry = class_auditentry(item)
		audit_entry_classes.append(auditentry)
		
	except:
		pass

menuchoice = ''
while menuchoice != 'x':

	#show main menu
	print_header();
	print_mainmenu()
	
	menuchoice = raw_input('Choice: ')
	try:
		print menuchoice[1]
		if int(menuchoice[1]) in range(1,16):
			callfunction = "run_menu_%s()" % menuchoice
			eval(callfunction)	
	except Exception, e:
		#print e.message
		pass


	raw_input('Press any key to continue')
