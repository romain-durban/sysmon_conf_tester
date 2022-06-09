# Sysmon Config Tester

## Purpose

The purpose of this project is to test a set of event log field values against a Sysmon configuration to verify if they would be included or excluded.

## Dependencies

None!

Script is based on the native XML parser Element Tree `xml.etree.ElementTree` which is a simple and fast implementation.
`xml.dom.minidom` is also used to prettyfy the output file.

## Usage

Put your Sysmon XML configuration in `sysmonconfig-export.xml` or use another filename but update the `sysmon_conf_tester.py` to import your file(s) instead.
The script allows to run on a list of configuration files which will be combined to build the rules set. This is useful when the configuration is defined in multiple files to seperate each Sysmon Event Type.

Write your tests in the `tests_input.xml` file. Structure is similar to the Sysmon configuration file:

```xml
<Tests>
	<NetworkConnect>
		<DestinationPort>22</DestinationPort>
	</NetworkConnect>
	<ProcessCreate>
		<CommandLine>C:\WINDOWS\Microsoft.NET\Framework64\v4.0.30319\Ngen.exe args1 args2</CommandLine>
	</ProcessCreate>
</Tests>
```

It is possible to supply a combination of values in the test by sorting them in a `<Rule></Rule>` tag, similarly to the way to define a Sysmon rule applying on several fields.

```xml
<ProcessCreate>
	<Rule>
		<Image>C:\Windows\System32\tasklist.exe</Image>
		<ParentImage>C:\Program Files\McAfee\Agent\masvc.exe</ParentImage>
	</Rule>
</ProcessCreate>
```

Results will be outputed in a XML file, sorted by match type. `none` match type is used when the value did not match any rule.
Note that a field value can match several match types.

## Author

Romain Durban (romain.durban@gmail.com)

# License

The project is licensed under MIT License
