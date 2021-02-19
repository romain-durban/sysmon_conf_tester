# Sysmon Config Tester

**WARNING** This project is still under development

## Purpose

The purpose of this project is to test a set of event log field values against a Sysmon configuration to verify if they would be included or excluded.

## Dependencies

None!

Script is based on the native XML parser Element Tree `xml.etree.ElementTree` which is a simple and fast implementation.

## Usage

Put your Sysmon XML configuration in `sysmonconfig-export.xml` or use another filename but update the `sysmon_conf_tester.py` to import your file instead.

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

Matched rules will be displayed in the output.

## Author

Romain Durban (romain.durban@gmail.com)

# License

The project is licensed under MIT License