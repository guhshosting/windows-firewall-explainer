param([Parameter(Mandatory)][string]$Executable)
$ErrorActionPreference='Stop'
function Require($Condition, $Message) { if(!$Condition) { throw $Message } }
foreach($mode in @('status','rules','explain')) {
 $arguments=@($mode,'--json')
 if($mode -eq 'explain') { $arguments+=@('--direction','inbound','--protocol','tcp','--profile','public','--local-port','443','--remote-ip','192.0.2.1') }
 $raw=& $Executable @arguments
 Require ($LASTEXITCODE -eq 0) "Live $mode failed"
 $doc=$raw | ConvertFrom-Json
 Require ($doc.schema_version -eq 1) 'Schema version'
 Require ($doc.profiles.Count -eq 3) 'Three profiles'
 Require ($doc.policy.local_rule_merge.status -eq 'unavailable') 'Merge status'
 Require ($null -eq $doc.policy.local_rule_merge.value) 'Null merge value'
 if($mode -eq 'explain') { Require ($doc.analysis.Count -eq $doc.rules.Count) 'Analysis coverage'; Require ($doc.tuple.local_port.value -eq '443') 'Tuple echo' }
}
foreach($arguments in @(
 @('status','--bogus','--json'),
 @('rules','--json','--json'),
 @('explain','--direction','inbound','--protocol','tcp','--profile','public','--remote-ip','example.com','--json'),
 @('explain','--direction','inbound','--protocol','tcp','--profile','public','--local-port','65536','--json'),
 @('explain','--direction','inbound','--protocol','tcp','--profile','public','--local-port','-1','--json'),
 @('explain','--json')
)) { $raw=& $Executable @arguments;Require ($LASTEXITCODE -eq 2) 'Invalid arguments exit';$doc=$raw | ConvertFrom-Json;Require ($doc.exit_code -eq 2) 'JSON error code' }
Write-Output 'Live modes, JSON schema/nulls and six malformed argument cases passed'
