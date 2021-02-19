import sys, os, re, json, logging
import xml.etree.ElementTree as ET

# Official doc: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

'''
ID 	Tag 	Event
1 ProcessCreate 	Process Create 	
2 FileCreateTime 	File creation time 	
3 NetworkConnect 	Network connection detected 	
4 n/a 	Sysmon service state change (cannot be filtered) 	
5 ProcessTerminate 	Process terminated 	
6 DriverLoad 	Driver Loaded 	
7 ImageLoad 	Image loaded 	
8 CreateRemoteThread 	CreateRemoteThread detected 	
9 RawAccessRead 	RawAccessRead detected 	
10 ProcessAccess 	Process accessed 	
11 FileCreate 	File created 	
12 RegistryEvent 	Registry object added or deleted 	
13 RegistryEvent 	Registry value set 	
14 RegistryEvent 	Registry object renamed 	
15 FileCreateStreamHash 	File stream created 	
16 n/a 	Sysmon configuration change (cannot be filtered) 	
17 PipeEvent 	Named pipe created 	
18 PipeEvent 	Named pipe connected 	
19 WmiEvent 	WMI filter 	
20 WmiEvent 	WMI consumer 	
21 WmiEvent 	WMI consumer filter 	
22 DNSQuery 	DNS query 	
23 FileDelete 	File Delete
'''

# ------------------
# Global functions
# ------------------
def matches_rule(r,value):
	'''Possible conditions:
		contains: 		value contains the condition
		excludes:		value does not contain the condition
		is: 			value and condition strictly equal
		is not: 		value strictly different to condition
		begin with: 	value starts with condition
		end with: 		value ends with condition
		image: 			equivalent to "is" but also matches text after the last "\"
		is any:			value is one of the ";" values in condition
		contains any:	value contains of the ";" values in condition
		excludes any:	value does not contain one or more of the ";" values in condition
		contains all:	value contains all of the ";" values in condition
		excludes all:	value does not contain any of the ";" values in condition
		more than:		Lexicographical comparison is more than zero
		less than:		Lexicographical comparison is less than zero
	'''
	t = r["text"]
	if "condition" in r:
		c = r["condition"]
	else:	# default comparison
		c = "is"

	if c == "contains":
		return (t in value)
	if c == "excludes":
		return (t not in value)
	if c== "is":
		return (t == value)
	if c == "is not":
		return not (t == value)
	if c == "begin with":
		return value.startswith(t)
	if c == "end with":
		return value.endswith(t)
	if c == "image":
		return (t == value) or (t == value.split("\\")[-1])
	mt = t.split(";")
	res = False
	if c == "is any":
		for tt in mt:
			res = res or (tt == value)
		return res
	if c == "contains any":
		for tt in mt:
			res = res or (tt in value)
		return res
	if c == "excludes any":
		for tt in mt:
			res = res or (tt not in value)
		return res
	res = True
	if c == "contains all":
		for tt in mt:
			res = res and (tt in value)
		return res
	if c == "excludes all":
		for tt in mt:
			res = res and (tt not in value)
		return res
	if c == "more than":
		return (value > t)
	if c == "less than":
		return (value < t)
	# by default (unknown condition), use "is"
	return (t == value)

# ------------------
# Global vars
# ------------------
rules = {}
tests = {}

# Using SwiftOnSecurity's sysmon config
# https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml
sysmon_tree = ET.parse('sysmonconfig-export.xml')
sysmon_root = sysmon_tree.getroot()

tests_tree = ET.parse('tests_input.xml')
tests_root = tests_tree.getroot()

# ------------------
# Importing rules
# ------------------
for rg in sysmon_root.find('EventFiltering').findall('RuleGroup'):
	for child in rg:
		event_type = child.tag
		match_type = child.attrib["onmatch"]
		if not event_type in rules:
			rules[event_type]={}

		rdic={}
		for r in child:
			field_name = r.tag
			if not field_name in rules[event_type]:
				rules[event_type][field_name] = {}
			if not match_type in rules[event_type][field_name]:
				rules[event_type][field_name][match_type] = []
			rules[event_type][field_name][match_type].append({"condition":r.attrib["condition"],"text":r.text})

# ------------------
# Importing tests
# ------------------
for et in tests_root:
	event_type = et.tag
	if not event_type in tests:
		tests[event_type] = {}
	for t in et:
		field_name = t.tag
		if not field_name in tests[event_type]:
			tests[event_type][field_name] = []
		tests[event_type][field_name].append({"value":t.text,"results":[]})

# ------------------
# Running tests
# ------------------
for et in tests:
	for fn in tests[et]:
		for i in range(len(tests[et][fn])):
			t = tests[et][fn][i]
			v = t["value"]
			if et in rules and fn in rules[et]:
				for mt in rules[et][fn]:
					for r in rules[et][fn][mt]:
						if matches_rule(r,v):
							print("* {} matched {}".format(v,r))
							tests[et][fn][i]["results"].append(mt)
print(tests)
		

