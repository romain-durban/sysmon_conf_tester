import glob
import xml.etree.ElementTree as ET
from xml.dom import minidom

# Official doc: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

'''
ID 	Tag 					Event
1 	ProcessCreate 			Process Create 	
2 	FileCreateTime 			File creation time 	
3 	NetworkConnect 			Network connection detected 	
4 	n/a 					Sysmon service state change (cannot be filtered) 	
5 	ProcessTerminate 		Process terminated 	
6 	DriverLoad 				Driver Loaded 	
7 	ImageLoad 				Image loaded 	
8 	CreateRemoteThread 		CreateRemoteThread detected 	
9 	RawAccessRead 			RawAccessRead detected 	
10 	ProcessAccess 			Process accessed 	
11 	FileCreate 				File created 	
12 	RegistryEvent 			Registry object added or deleted 	
13 	RegistryEvent 			Registry value set 	
14 	RegistryEvent 			Registry object renamed 	
15 	FileCreateStreamHash 	File stream created 	
16 	n/a 					Sysmon configuration change (cannot be filtered) 	
17 	PipeEvent 				Named pipe created 	
18 	PipeEvent 				Named pipe connected 	
19 	WmiEvent 				WMI filter 	
20 	WmiEvent 				WMI consumer 	
21 	WmiEvent 				WMI consumer filter 	
22 	DNSQuery 				DNS query 	
23 	FileDelete 				File Delete archived
24	ClipboardChange			Clipboard change (New content in the clipboard)
25 	ProcessTampering		Process image change
26	FileDeleteDetected		File Delete not archived
'''
SYSMON_EVENT_TYPES = {
	"ProcessCreate": "1",
	"FileCreateTime": "2",
	"NetworkConnect": "3",
	"ProcessTerminate": "5",
	"DriverLoad": "6",
	"ImageLoad": "7",
	"CreateRemoteThread": "8",
	"RawAccessRead": "9",
	"ProcessAccess": "10",
	"FileCreate": "11",
	"RegistryEvent": "12,13,14",
	"FileCreateStreamHash": "15",
	"PipeEvent": "17,18",
	"WmiEvent": "19,20,21",
	"DNSQuery": "22",
	"FileDelete": "23",
	"ClipboardChange": "24",
	"ProcessTampering": "25",
	"FileDeleteDetected": "26"
}

SYSMON_MATCH_TYPES = {
	"include": "Values included by the configuration",
	"exclude": "Values excluded by the configuration",
	"none": "No rule explictly applies to these values"
}

# ------------------
# Global functions
# ------------------
# Tests if a rule matches the given value
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
	# Sysmon comparisons are case insensitive
	t = r["text"].lower()
	if isinstance(value,list):
		low_value = [v.lower() for v in value]
	else:
		low_value = value.lower()
	if "condition" in r:
		c = r["condition"]
	else:	# default comparison
		c = "is"

	if c == "contains":
		return (t in low_value)
	if c == "excludes":
		return (t not in low_value)
	if c== "is":
		return (t == low_value)
	if c == "is not":
		return not (t == low_value)
	if c == "begin with":
		return low_value.startswith(t)
	if c == "end with":
		return low_value.endswith(t)
	if c == "image":
		return (t == low_value) or (t == low_value.split("\\")[-1])
	mt = t.split(";")
	res = False
	if c == "is any":
		for tt in mt:
			res = res or (tt == low_value)
		return res
	if c == "contains any":
		for tt in mt:
			res = res or (tt in low_value)
		return res
	if c == "excludes any":
		for tt in mt:
			res = res or (tt not in low_value)
		return res
	res = True
	if c == "contains all":
		for tt in mt:
			res = res and (tt in low_value)
		return res
	if c == "excludes all":
		for tt in mt:
			res = res and (tt not in low_value)
		return res
	# For lexicographical comparisons, we keep the case intact
	if c == "more than":
		return (value > r["text"])
	if c == "less than":
		return (value < r["text"])
	# by default (unknown condition), use "is"
	return (t == low_value)

# Evaluates if the test case matches the given rule
def evaluateTest(rule,test):
	'''
	Test structure:
		values: [
			{"field":CommandLine,"value":"ABC"}
			...
		],
		results: [...],
		requires: {list of necessary fields}

	Rule structure:
		"operator":"or",
		"filters":[
			{"field":CommandLine,"condition":"is","text":"ABC"}
			...
		],
		requires: {list of necessary fields}
	'''
	# To save some time, we run the test only if the test and the rule apply on at least 1 field in common
	if not any(item in rule["requires"] for item in test["requires"]):
		return False

	global_result = None

	for f in rule["filters"]:
		filter_result = False
		for v in test["values"]:
			if v["field"] == f["field"]:
				filter_result = filter_result or matches_rule(f,v["value"])
		if global_result is None:
			global_result = filter_result
		else:
			if rule["operator"].lower() == "or":
				global_result = global_result or filter_result
				if global_result:
					return True
			else:
				global_result = global_result and filter_result
				if not global_result:
					return False

	return global_result

# ------------------
# Global vars
# ------------------
rules = {}
tests = {}
mt_results = {"none":{}}

# ------------------
# Importing rules
# ------------------
# EventFiltering contains the definition of filters, sorted into several RuleGroup
# We here assume RuleGroup always uses groupRelation="or" because it makes more sense
# Using SwiftOnSecurity's sysmon config
# https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml

configs = ['sysmonconfig-export.xml']
# configs = glob.glob("configs_folder\\*.xml")

for conf in configs:
	# Importing Sysmon XML config
	sysmon_tree = ET.parse(conf)
	sysmon_root = sysmon_tree.getroot()
	for rg in sysmon_root.find('EventFiltering').findall('RuleGroup'):
		# At this level we expect to see (preferably) one Sysmon event type (corresponding to an EventID)
		# With a given "onmatch" action, either include or exclude
		for child in rg:
			event_type = child.tag
			match_type = child.attrib["onmatch"]
			if not event_type in rules:
				rules[event_type]={}
			if not match_type in rules[event_type]:
				rules[event_type][match_type] = []

			# We want to sort filters/rules in a structure that looks like the following (to ease its use)
			# EventType > MatchType > Filter/Rule
			for r in child:
				# At this point we either expect a single filter or a Rule (a combination of several filters)
				# In either case, we buid the list of filters to apply
				if r.tag == "Rule":
					obj = {"operator":r.attrib["groupRelation"],"filters":[],"requires":set()}
					for f in r:
						field_name = f.tag
						# Default condition is "is"
						obj["requires"].add(field_name)
						obj["filters"].append({"field":field_name,"condition":f.attrib["condition"] if "condition" in f.attrib else "is","text":f.text})
					rules[event_type][match_type].append(obj)
				else:
					field_name = r.tag
					# Default condition is "is"
					rules[event_type][match_type].append({"operator":"or","requires":{field_name},"filters":[{"field":field_name,"condition":r.attrib["condition"] if "condition" in r.attrib else "is","text":r.text}]})

# ------------------
# Importing tests
# ------------------
#Importing test file to run
tests_tree = ET.parse('tests_input.xml')
tests_root = tests_tree.getroot()

for et in tests_root:
	event_type = et.tag
	if not event_type in tests:
		tests[event_type] = []
	for t in et:
		field_name = t.tag
		# Just like it is done in the Sysmon configuration
		# We allow a test to supply multiple fields using the Rule tag
		if field_name == "Rule":
			values=[]
			fields=set()
			for f in t:
				fields.add(f.tag)
				values.append({"field":f.tag,"value":f.text,"results":[]})
			tests[event_type].append({"values":values,"results":[],"requires":fields})
		else:
			tests[event_type].append({"values":[{"field":field_name,"value":t.text}],"results":[],"requires":{field_name}})

# ------------------
# Running tests
# ------------------
for et in tests:
	for i in range(len(tests[et])):
		t = tests[et][i]
		if et in rules:
			for mt in rules[et]:
				for r in rules[et][mt]:
					if evaluateTest(r,t):
						#print("* {} matched {}".format(v,r))
						tests[et][i]["results"].append(mt)
						if not mt in mt_results:
							mt_results[mt] = {}
						if not et in mt_results[mt]:
							mt_results[mt][et] = []
						mt_results[mt][et].append(t)
			if len(tests[et][i]["results"]) == 0:
				if not et in mt_results["none"]:
					mt_results["none"][et] = []
				mt_results["none"][et].append(t)
		# Missing configuration for this event type, moving to "none" directly
		else:
			if not et in mt_results["none"]:
				mt_results["none"][et] = []
			mt_results["none"][et].append(t)
		
#Output in XML file
res_el = ET.Element('Results')
# Root node
for mt in mt_results:
	# Match Type node
	res_el.append(ET.Comment("Match type \"{}\" : {}".format(mt,SYSMON_MATCH_TYPES[mt]))) 
	mt_el = ET.SubElement(res_el, mt)
	for et in mt_results[mt]:
		# Event Type node
		mt_el.append(ET.Comment("Sysmon event {} - EventID {}".format(et,SYSMON_EVENT_TYPES[et]))) 
		et_el = ET.SubElement(mt_el, et)
		# Print back the test with either the value or the Rule tag containing the multiple values
		for entry in mt_results[mt][et]:
			if len(entry["values"]) == 1:
				v = entry["values"][0]
				res_entry = ET.SubElement(et_el, v["field"])
				res_entry.text = v["value"]
			else:
				rule_entry = ET.SubElement(et_el, "Rule")
				for v in entry["values"]:
					res_entry = ET.SubElement(rule_entry, v["field"])
					res_entry.text = v["value"]

tree = ET.ElementTree(res_el)

#Using minidom for outputing a prettier text
xmlstr = minidom.parseString(ET.tostring(res_el,short_empty_elements=False)).toprettyxml(indent="   ")
with open("test_output.xml", "w") as f:
    f.write(xmlstr)