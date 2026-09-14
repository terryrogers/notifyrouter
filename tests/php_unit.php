<?php
declare(strict_types=1);

$root=dirname(__DIR__);
$testDir=getenv('NOTIFYROUTER_TEST_DIR')?:sys_get_temp_dir().'/notifyrouter-unit-'.bin2hex(random_bytes(4));
if(!is_dir($testDir)&&!mkdir($testDir,0700,true))throw new RuntimeException('Unable to create test directory');
$config=$testDir.'/config.php';
$key=sodium_bin2base64(str_repeat("\x01",SODIUM_CRYPTO_SECRETBOX_KEYBYTES),SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
file_put_contents($config,"<?php return ".var_export(['database'=>$testDir.'/test.sqlite3','master_key'=>$key,'webhook_token'=>'unit-webhook-token','setup_token'=>'unit-setup-token','event_log'=>$testDir.'/events.ndjson'],true).";\n");
putenv('NOTIFYROUTER_CONFIG='.$config);
define('NOTIFYROUTER_BOOTSTRAP_ONLY',true);
require $root.'/php/app.php';

$passed=0;
function check(bool $condition,string $message): void {global $passed;if(!$condition)throw new RuntimeException($message);$passed++;}
function same(mixed $expected,mixed $actual,string $message): void {check($expected===$actual,$message.' expected '.var_export($expected,true).' got '.var_export($actual,true));}
function totp_code(string $secret,int $counter): string {
    $key=base32_decode_secret($secret);$binary='';for($i=7;$i>=0;$i--)$binary.=chr(($counter>>($i*8))&0xff);
    $hash=hash_hmac('sha1',$binary,$key,true);$offset=ord($hash[19])&15;
    $number=((ord($hash[$offset])&127)<<24)|((ord($hash[$offset+1])&255)<<16)|((ord($hash[$offset+2])&255)<<8)|(ord($hash[$offset+3])&255);
    return str_pad((string)($number%1000000),6,'0',STR_PAD_LEFT);
}

$database=db();
$tables=array_column($database->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_ASSOC),'name');
foreach(['settings','rules','events','reset_tokens','roles','role_permissions','users','destinations','outbound_templates','audit_log'] as$table)check(in_array($table,$tables,true),'Missing table '.$table);
same(2,(int)$database->query('SELECT COUNT(*) FROM roles')->fetchColumn(),'Built-in role count');
$adminId=(int)$database->query("SELECT id FROM roles WHERE name='Administrator'")->fetchColumn();
$userId=(int)$database->query("SELECT id FROM roles WHERE name='User'")->fetchColumn();
same(count(PERMISSIONS),count(role_permissions($adminId)),'Administrator permission count');
same(['Manage Inbound Rules','Manage Outbound Templates','View Payload Log','View Recent Events'],role_permissions($userId),'User permissions');

setv('sample','value');same('value',setting('sample'),'Settings round trip');same('fallback',setting('missing','fallback'),'Settings default');
$encrypted=enc('secret value');check($encrypted!=='secret value','Encryption must transform plaintext');same('secret value',dec($encrypted),'Encryption round trip');same('',dec('invalid'),'Invalid ciphertext handling');

$payload=['alarm_id'=>'a1','events'=>[['alert_key'=>'CLIENT_CONNECTED','scope'=>['site_id'=>'s1']]],'count'=>3];
$flat=flat($payload);same('CLIENT_CONNECTED',$flat['events.0.alert_key'],'Nested flattening');same(['CLIENT_CONNECTED'],values_for($flat,'events.*.alert_key'),'Wildcard lookup');same([],values_for($flat,'missing'),'Missing lookup');
$conditions=[
 ['path'=>'alarm_id','operator'=>'equals','value'=>'a1'],['path'=>'alarm_id','operator'=>'not_equals','value'=>'x'],
 ['path'=>'alarm_id','operator'=>'contains','value'=>'1'],['path'=>'alarm_id','operator'=>'starts_with','value'=>'a'],
 ['path'=>'alarm_id','operator'=>'ends_with','value'=>'1'],['path'=>'alarm_id','operator'=>'regex','value'=>'^a\\d$'],
 ['path'=>'count','operator'=>'gt','value'=>2],['path'=>'count','operator'=>'gte','value'=>3],
 ['path'=>'count','operator'=>'lt','value'=>4],['path'=>'count','operator'=>'lte','value'=>3],
 ['path'=>'alarm_id','operator'=>'in','value'=>'a1,a2'],['path'=>'alarm_id','operator'=>'exists','value'=>''],
 ['path'=>'missing','operator'=>'not_exists','value'=>'']
];
foreach($conditions as$condition)check(condition_matches($condition,$flat),'Condition failed: '.$condition['operator']);
check(!condition_matches(['path'=>'alarm_id','operator'=>'equals','value'=>'wrong'],$flat),'Non-match condition');
same('Alert <b>a1</b>',render_message('Alert <b>{{ alarm_id }}</b>',$flat),'Template rendering');
same('&lt;script&gt;',render_message('{{ value }}',['value'=>'<script>']),'Payload escaping');

$now=gmdate(DATE_ATOM);
$database->prepare('INSERT INTO destinations(name,description,type,configuration,enabled,created_at,updated_at)VALUES(?,?,?,?,?,?,?)')->execute(['Disabled Push','Test','pushover','{}',0,$now,$now]);
$destinationId=(int)$database->lastInsertId();
$database->prepare('INSERT INTO outbound_templates(name,description,destination_id,title_template,message_template,html,created_at,updated_at)VALUES(?,?,?,?,?,?,?,?)')->execute(['Client Alert','Test',$destinationId,'Event {{ events.0.alert_key }}','Site <b>{{ events.0.scope.site_id }}</b>',1,$now,$now]);
$templateId=(int)$database->lastInsertId();
$insert=$database->prepare("INSERT INTO rules(name,enabled,priority,match_mode,conditions,title_template,message_template,html,pushover_priority,sound,stop_processing,template_id)VALUES(?,?,?,?,?,'','',1,0,'pushover',?,?)");
$insert->execute(['Connected',1,10,'all',json_encode([['path'=>'events.*.alert_key','operator'=>'equals','value'=>'CLIENT_CONNECTED']]),1,$templateId]);
$insert->execute(['Should Not Run',1,20,'all','[]',0,$templateId]);
[$variables,$outputs]=evaluate($payload);same('a1',$variables['alarm_id'],'Evaluate variables');same(1,count($outputs),'Stop processing');same('Connected',$outputs[0]['rule'],'Matched rule');same('Event CLIENT_CONNECTED',$outputs[0]['title'],'Rendered title');same('Site <b>s1</b>',$outputs[0]['message'],'Rendered message');same('destination:not_available',deliver($outputs[0]),'Disabled destination behavior');
$database->prepare("INSERT INTO rules(name,enabled,priority,match_mode,conditions,title_template,message_template,html,pushover_priority,sound,stop_processing,template_id)VALUES('No Template',1,1,'all','[]','','',1,0,'pushover',0,NULL)")->execute();
[$unused,$withoutLegacy]=evaluate(['anything'=>true]);same([],array_values(array_filter($withoutLegacy,fn($o)=>$o['rule']==='No Template')),'Unassigned rules produce no legacy output');

$binary=random_bytes(20);$secret=base32_encode_secret($binary);same($binary,base32_decode_secret($secret),'Base32 round trip');
$code=totp_code($secret,(int)floor(time()/30));check(totp_valid($secret,$code),'Valid current TOTP');check(!totp_valid($secret,'00000'),'Invalid TOTP format');
same(false,feed_has_issue('<rss><title>All Systems Operational</title></rss>'),'Healthy status feed');
same(true,feed_has_issue('<rss><description>Service disruption</description></rss>'),'Incident status feed');
setv('pushover_operational','1');same('unset',pushover_status()['level'],'Pushover requires enabled destination');
setv('email_operational','1');same('unset',smtp_probe()['level'],'Email requires enabled destination');

$_SESSION=['user_name'=>'Unit Tester'];$_SERVER['REMOTE_ADDR']='127.0.0.1';audit('Configuration Change','Unit test');
same(1,(int)$database->query('SELECT COUNT(*) FROM audit_log')->fetchColumn(),'Audit insert');
log_event(['status'=>'unit']);check(is_file($testDir.'/events.ndjson'),'Payload log created');same('unit',json_decode(trim((string)file_get_contents($testDir.'/events.ndjson')),true)['status'],'Payload log content');
$_SESSION=['permissions'=>['View Recent Events']];check(can('View Recent Events'),'Granted permission');check(!can('Administrator'),'Denied permission');
$_SESSION=['permissions'=>['Administrator']];check(can('Clear Payload Log'),'Administrator wildcard permission');
$_SESSION=['legacy_admin'=>true];check(can('Administrator'),'Recovery administrator permission');
$_SESSION=['admin'=>true];refresh_session_authorization();check(can_access_administration(),'Existing legacy administrator session authorization refresh');

echo "PHP unit tests passed: {$passed} assertions\n";
