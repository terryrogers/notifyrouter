<?php
declare(strict_types=1);

const NOTIFYROUTER_VERSION = '0.4.1';
define('NOTIFYROUTER_CONFIG',getenv('NOTIFYROUTER_CONFIG')?:dirname(__DIR__).'/.notifyrouter/config.php');
const NOTIFYROUTER_GITHUB = 'https://github.com/terryrogers/notifyrouter';
const NOTIFYROUTER_AUTHOR = 'https://www.terryrogers.me';

function cfg(): array {
    $config = require NOTIFYROUTER_CONFIG;
    if (!is_array($config)) throw new RuntimeException('Configuration unavailable');
    return $config;
}
function db(): PDO {
    static $db;
    if ($db instanceof PDO) return $db;
    $db = new PDO('sqlite:' . cfg()['database'], null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $db->exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000');
    $db->exec("CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,priority INTEGER NOT NULL DEFAULT 100,match_mode TEXT NOT NULL DEFAULT 'all',conditions TEXT NOT NULL DEFAULT '[]',title_template TEXT NOT NULL,message_template TEXT NOT NULL,html INTEGER NOT NULL DEFAULT 1,pushover_priority INTEGER NOT NULL DEFAULT 0,sound TEXT NOT NULL DEFAULT 'pushover',stop_processing INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,received_at TEXT NOT NULL,payload TEXT NOT NULL,variables TEXT NOT NULL,matched_rules TEXT NOT NULL,status TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS reset_tokens(id INTEGER PRIMARY KEY AUTOINCREMENT,token_hash TEXT NOT NULL,expires_at INTEGER NOT NULL,used_at INTEGER);
      CREATE TABLE IF NOT EXISTS roles(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE,built_in INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS role_permissions(role_id INTEGER NOT NULL,permission TEXT NOT NULL,PRIMARY KEY(role_id,permission),FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE);
      CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE,full_name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role_id INTEGER NOT NULL,enabled INTEGER NOT NULL DEFAULT 0,two_factor_secret TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(role_id) REFERENCES roles(id));
      CREATE TABLE IF NOT EXISTS destinations(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',type TEXT NOT NULL CHECK(type IN ('pushover','email')),configuration TEXT NOT NULL DEFAULT '{}',enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS outbound_templates(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',destination_id INTEGER,title_template TEXT NOT NULL DEFAULT '',message_template TEXT NOT NULL DEFAULT '',html INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(destination_id) REFERENCES destinations(id));
      CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,occurred_at TEXT NOT NULL,user_name TEXT NOT NULL,event TEXT NOT NULL,details TEXT NOT NULL,remote_address TEXT NOT NULL DEFAULT '');
      CREATE INDEX IF NOT EXISTS idx_audit_log_occurred_at ON audit_log(occurred_at DESC);
      CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);
      CREATE INDEX IF NOT EXISTS idx_destinations_type ON destinations(type)");
    ensure_column($db,'rules','template_id','INTEGER');ensure_column($db,'reset_tokens','user_id','INTEGER');
    seed_security_model($db);
    return $db;
}

const PERMISSIONS = [
    'Read-only Administrator','Read-only','Administrator','Manage Inbound Rules',
    'Manage Outbound Templates','View Recent Events','Clear Recent Events',
    'View Payload Log','Clear Payload Log'
];

function ensure_column(PDO $db,string $table,string $column,string $definition): void {
    $columns=array_column($db->query('PRAGMA table_info('.$table.')')->fetchAll(PDO::FETCH_ASSOC),'name');
    if(!in_array($column,$columns,true))$db->exec('ALTER TABLE '.$table.' ADD COLUMN '.$column.' '.$definition);
}

function seed_security_model(PDO $db): void {
    $db->exec("INSERT OR IGNORE INTO roles(name,built_in) VALUES('Administrator',1),('User',1)");
    $admin=(int)$db->query("SELECT id FROM roles WHERE name='Administrator'")->fetchColumn();
    $user=(int)$db->query("SELECT id FROM roles WHERE name='User'")->fetchColumn();
    $insert=$db->prepare('INSERT OR IGNORE INTO role_permissions(role_id,permission)VALUES(?,?)');
    foreach(PERMISSIONS as $permission)$insert->execute([$admin,$permission]);
    foreach(['Manage Inbound Rules','Manage Outbound Templates','View Recent Events','View Payload Log'] as $permission)$insert->execute([$user,$permission]);
}

function audit(string $event,string $details='',?string $user=null): void {
    $name=$user??(string)($_SESSION['user_name']??'System');
    $q=db()->prepare('INSERT INTO audit_log(occurred_at,user_name,event,details,remote_address)VALUES(?,?,?,?,?)');
    $q->execute([gmdate(DATE_ATOM),$name,$event,$details,(string)($_SERVER['REMOTE_ADDR']??'')]);
}

function role_permissions(int $roleId): array {
    $q=db()->prepare('SELECT permission FROM role_permissions WHERE role_id=? ORDER BY permission');$q->execute([$roleId]);
    return array_column($q->fetchAll(PDO::FETCH_ASSOC),'permission');
}

function can(string $permission): bool {
    if(!empty($_SESSION['legacy_admin']))return true;
    $permissions=$_SESSION['permissions']??[];
    return in_array('Administrator',$permissions,true)||in_array($permission,$permissions,true);
}

function can_access_administration(): bool {
    return can('Read-only Administrator') || can('Administrator');
}

function refresh_session_authorization(): void {
    if(empty($_SESSION['admin']))return;
    if(!empty($_SESSION['user_id'])){
        $q=db()->prepare('SELECT u.enabled,u.full_name,u.role_id FROM users u WHERE u.id=? LIMIT 1');
        $q->execute([(int)$_SESSION['user_id']]);$user=$q->fetch(PDO::FETCH_ASSOC);
        if(!$user||!$user['enabled']){$_SESSION=[];session_destroy();return;}
        $_SESSION['user_name']=$user['full_name'];
        $_SESSION['permissions']=role_permissions((int)$user['role_id']);
        return;
    }
    $_SESSION['legacy_admin']=true;
    $_SESSION['user_name']='Administrator';
    $_SESSION['permissions']=PERMISSIONS;
}

function require_permission(string $permission): void {
    if(!can($permission)){http_response_code(403);exit('Permission denied');}
}
function base32_decode_secret(string $secret): string|false {
    $alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';$secret=strtoupper(preg_replace('/[^A-Z2-7]/i','',$secret));$bits='';
    foreach(str_split($secret)as$char){$position=strpos($alphabet,$char);if($position===false)return false;$bits.=str_pad(decbin($position),5,'0',STR_PAD_LEFT);}
    $result='';foreach(str_split($bits,8)as$byte)if(strlen($byte)===8)$result.=chr(bindec($byte));return$result;
}
function base32_encode_secret(string $value): string {
    $alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';$bits='';foreach(str_split($value)as$char)$bits.=str_pad(decbin(ord($char)),8,'0',STR_PAD_LEFT);$out='';foreach(str_split($bits,5)as$chunk){if(strlen($chunk)<5)$chunk=str_pad($chunk,5,'0');$out.=$alphabet[bindec($chunk)];}return$out;
}
function totp_valid(string $secret,string $code): bool {
    if(!preg_match('/^\d{6}$/',$code))return false;$key=base32_decode_secret($secret);if($key===false)return false;$counter=(int)floor(time()/30);
    for($offset=-1;$offset<=1;$offset++){$value=$counter+$offset;$binary='';for($i=7;$i>=0;$i--)$binary.=chr(($value>>($i*8))&0xff);$hash=hash_hmac('sha1',$binary,$key,true);$index=ord($hash[19])&15;$number=((ord($hash[$index])&127)<<24)|((ord($hash[$index+1])&255)<<16)|((ord($hash[$index+2])&255)<<8)|(ord($hash[$index+3])&255);if(hash_equals(str_pad((string)($number%1000000),6,'0',STR_PAD_LEFT),$code))return true;}return false;
}
function setting(string $key, string $default=''): string {
    $q=db()->prepare('SELECT value FROM settings WHERE key=?'); $q->execute([$key]); $v=$q->fetchColumn();
    return $v===false ? $default : (string)$v;
}
function setv(string $key, string $value): void {
    $q=db()->prepare('INSERT INTO settings(key,value)VALUES(?,?) ON CONFLICT(key)DO UPDATE SET value=excluded.value'); $q->execute([$key,$value]);
}
function enc(string $value): string {
    if ($value==='') return '';
    $key=sodium_base642bin(cfg()['master_key'],SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $nonce=random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return sodium_bin2base64($nonce.sodium_crypto_secretbox($value,$nonce,$key),SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
}
function dec(string $value): string {
    if ($value==='') return '';
    try {
        $raw=sodium_base642bin($value,SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        $nonce=substr($raw,0,SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $key=sodium_base642bin(cfg()['master_key'],SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        $plain=sodium_crypto_secretbox_open(substr($raw,SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),$nonce,$key);
        return $plain===false ? '' : $plain;
    } catch(Throwable) { return ''; }
}
function flat(mixed $value,string $prefix=''): array {
    $out=[]; if($prefix!=='') $out[$prefix]=$value;
    if(is_array($value)) foreach($value as $key=>$child) $out += flat($child,$prefix===''?(string)$key:$prefix.'.'.$key);
    return $out;
}
function values_for(array $vars,string $path): array {
    if(!str_contains($path,'*')) return array_key_exists($path,$vars)?[$vars[$path]]:[];
    $regex='/^'.str_replace('\\*','[^.]+',preg_quote($path,'/')).'$/';
    return array_values(array_filter($vars,fn($v,$k)=>preg_match($regex,(string)$k)===1,ARRAY_FILTER_USE_BOTH));
}
function condition_matches(array $c,array $vars): bool {
    $values=values_for($vars,(string)($c['path']??'')); $op=(string)($c['operator']??'equals'); $wanted=$c['value']??null;
    if($op==='exists') return count($values)>0;
    if($op==='not_exists') return count($values)===0;
    foreach($values as $actual) {
        $a=is_scalar($actual)?(string)$actual:json_encode($actual); $w=is_scalar($wanted)?(string)$wanted:json_encode($wanted);
        $ok=match($op){
            'equals'=>$actual===$wanted||$a===$w, 'not_equals'=>!($actual===$wanted||$a===$w),
            'contains'=>str_contains($a,$w), 'starts_with'=>str_starts_with($a,$w), 'ends_with'=>str_ends_with($a,$w),
            'regex'=>@preg_match('~'.$w.'~',$a)===1,
            'gt'=>is_numeric($a)&&is_numeric($w)&&(float)$a>(float)$w, 'gte'=>is_numeric($a)&&is_numeric($w)&&(float)$a>=(float)$w,
            'lt'=>is_numeric($a)&&is_numeric($w)&&(float)$a<(float)$w, 'lte'=>is_numeric($a)&&is_numeric($w)&&(float)$a<=(float)$w,
            'in'=>in_array($a,is_array($wanted)?array_map('strval',$wanted):array_map('trim',explode(',',$w)),true), default=>false
        };
        if($ok) return true;
    }
    return false;
}
function render_message(string $template,array $vars): string {
    return preg_replace_callback('/\{\{\s*([^{}]+?)\s*\}\}/',function($m)use($vars){
        $value=$vars[trim($m[1])]??''; if(is_array($value))$value=json_encode($value,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        return htmlspecialchars((string)$value,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');
    },$template)??'';
}
function evaluate(array $payload): array {
    $vars=flat($payload); $outputs=[];
    foreach(db()->query('SELECT r.*,t.name output_name,t.title_template output_title,t.message_template output_message,t.html output_html,t.destination_id FROM rules r LEFT JOIN outbound_templates t ON t.id=r.template_id WHERE r.enabled=1 ORDER BY r.priority,r.id')->fetchAll(PDO::FETCH_ASSOC) as $rule) {
        $conditions=json_decode($rule['conditions'],true)?:[]; $results=array_map(fn($c)=>condition_matches($c,$vars),$conditions);
        $matched=$rule['match_mode']==='any'?in_array(true,$results,true):!in_array(false,$results,true);
        if(!$matched) continue;
        if($rule['output_name']===null)continue;
        $outputs[]=['rule'=>$rule['name'],'template'=>$rule['output_name'],'destination_id'=>$rule['destination_id'],'title'=>render_message((string)$rule['output_title'],$vars),'message'=>render_message((string)$rule['output_message'],$vars),'html'=>(bool)$rule['output_html'],'priority'=>(int)$rule['pushover_priority'],'sound'=>$rule['sound']];
        if($rule['stop_processing']) break;
    }
    return [$vars,$outputs];
}
function http_probe(string $url): array {
    $ch=curl_init($url); curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>6,CURLOPT_CONNECTTIMEOUT=>4,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_USERAGENT=>'NotifyRouter/'.NOTIFYROUTER_VERSION]);
    $body=curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_RESPONSE_CODE); $error=curl_error($ch); curl_close($ch);
    return ['reachable'=>$body!==false&&$code>=200&&$code<500,'code'=>$code,'body'=>$body===false?'':(string)$body,'error'=>$error];
}
function feed_has_issue(string $body): bool {
    if($body==='') return true;
    if(preg_match_all('/<(?:title|description)>(.*?)<\/(?:title|description)>/is',$body,$matches)) {
        foreach($matches[1] as $text) {
            $plain=strtolower(strip_tags(html_entity_decode($text)));
            if(str_contains($plain,'degraded')||str_contains($plain,'outage')||str_contains($plain,'disruption')||str_contains($plain,'unavailable')||str_contains($plain,'maintenance')) return true;
        }
    }
    return false;
}
function pushover_status(): array {
    $destinationCount=(int)db()->query("SELECT COUNT(*) FROM destinations WHERE type='pushover' AND enabled=1")->fetchColumn();
    if(setting('pushover_operational','0')!=='1'||$destinationCount<1)return ['level'=>'unset','label'=>'Disabled','note'=>$destinationCount?'Operational monitoring is disabled.':'Configure and enable at least one Pushover destination.'];
    $api=http_probe('https://api.pushover.net/1/messages.json'); $feed=http_probe(setting('pushover_status_rss','https://status.pushover.net/rss')); $issue=!$feed['reachable']||feed_has_issue($feed['body']);
    if($api['reachable']&&!$issue) return ['level'=>'up','label'=>'Operational','note'=>'API and status feed are healthy.'];
    if($api['reachable']) return ['level'=>'warn','label'=>'Degraded','note'=>'The message API is reachable, but the Pushover status feed reports an issue.'];
    if($issue) return ['level'=>'down','label'=>'Down','note'=>'The message API check failed and the Pushover status feed reports an issue.'];
    return ['level'=>'warn','label'=>'Uncertain','note'=>'The API check failed while the status feed reports no incident.'];
}
function smtp_probe(): array {
    $destinationCount=(int)db()->query("SELECT COUNT(*) FROM destinations WHERE type='email' AND enabled=1")->fetchColumn();
    if(setting('email_operational','0')!=='1'||$destinationCount<1)return ['level'=>'unset','label'=>'Disabled','note'=>$destinationCount?'Operational monitoring is disabled.':'Configure and enable at least one email destination.'];
    $host=setting('smtp_test_host',setting('smtp_host')); $port=(int)setting('smtp_test_port',setting('smtp_port','587')); $url=setting('smtp_status_url');
    if($host==='') return ['level'=>'unset','label'=>'Not Configured','note'=>'Enter SMTP settings to enable email.'];
    $errno=0;$err='';$socket=@stream_socket_client(($port===465?'ssl://':'tcp://').$host.':'.$port,$errno,$err,5);$reachable=is_resource($socket);if($reachable)fclose($socket);
    $issue=false;if($url!==''){$page=http_probe($url);$issue=!$page['reachable']||preg_match('/degraded|outage|incident|disruption|unavailable/i',$page['body'])===1;}
    if($reachable&&!$issue)return['level'=>'up','label'=>'Operational','note'=>'SMTP endpoint and provider status page are healthy.'];
    if($reachable)return['level'=>'warn','label'=>'Degraded','note'=>'SMTP is reachable, but the provider status page reports an issue.'];
    if($issue)return['level'=>'down','label'=>'Down','note'=>'SMTP is unreachable and the provider status page reports an issue.'];
    return['level'=>'warn','label'=>'Uncertain','note'=>'SMTP is unreachable while no provider incident is reported.'];
}
function smtp_command($socket,string $command,array $expected): bool {
    if($command!=='') fwrite($socket,$command."\r\n"); $reply='';
    do{$line=fgets($socket,1024);if($line===false)return false;$reply.=$line;}while(strlen($line)>3&&$line[3]==='-');
    return in_array((int)substr($reply,0,3),$expected,true);
}
function send_email(string $to,string $subject,string $html): string {
    $host=setting('smtp_host');$port=(int)setting('smtp_port','587');$security=setting('smtp_security','starttls');$user=setting('smtp_user');$password=dec(setting('smtp_password'));$from=setting('smtp_from',$user);$name=setting('smtp_from_name','NotifyRouter');
    if($host===''||!filter_var($to,FILTER_VALIDATE_EMAIL)||!filter_var($from,FILTER_VALIDATE_EMAIL))return'not_configured';$subject=str_replace(["\r","\n"],' ',$subject);$name=str_replace(["\r","\n"],' ',$name);$prefix=$security==='ssl'?'ssl://':'tcp://';$errno=0;$err='';$s=@stream_socket_client($prefix.$host.':'.$port,$errno,$err,10);if(!$s)return'failed:connect';stream_set_timeout($s,10);
    if(!smtp_command($s,'',[220])||!smtp_command($s,'EHLO notifyrouter.local',[250])){fclose($s);return'failed:greeting';}
    if($security==='starttls'){if(!smtp_command($s,'STARTTLS',[220])||!stream_socket_enable_crypto($s,true,STREAM_CRYPTO_METHOD_TLS_CLIENT)||!smtp_command($s,'EHLO notifyrouter.local',[250])){fclose($s);return'failed:tls';}}
    if($user!==''&&!smtp_command($s,'AUTH LOGIN',[334])){fclose($s);return'failed:auth';}
    if($user!==''&&(!smtp_command($s,base64_encode($user),[334])||!smtp_command($s,base64_encode($password),[235]))){fclose($s);return'failed:auth';}
    if(!smtp_command($s,'MAIL FROM:<'.$from.'>',[250])||!smtp_command($s,'RCPT TO:<'.$to.'>',[250,251])||!smtp_command($s,'DATA',[354])){fclose($s);return'failed:recipient';}
    $type=setting('email_message_type','html');$body=$html.setting('email_footer');if($type==='plain')$body=html_entity_decode(strip_tags(str_replace(['<br>','<br/>','<br />'],"\n",$body)));
    $headers='From: '.$name.' <'.$from.">\r\n".'To: <'.$to.">\r\n".'Subject: '.$subject."\r\n".'MIME-Version: 1.0'."\r\n".'Content-Type: '.($type==='plain'?'text/plain':'text/html').'; charset=UTF-8'."\r\n";
    fwrite($s,$headers."\r\n".str_replace("\n.","\n..",$body)."\r\n.\r\n");$ok=smtp_command($s,'',[250]);smtp_command($s,'QUIT',[221]);fclose($s);return$ok?'sent':'failed:data';
}
function send_pushover(array $output): string {
    $token=dec(setting('pushover_token'));$user=dec(setting('pushover_user'));if($token===''||$user==='')return'not_configured';
    $ch=curl_init('https://api.pushover.net/1/messages.json');curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>10,CURLOPT_POSTFIELDS=>['token'=>$token,'user'=>$user,'title'=>substr($output['title'],0,250),'message'=>substr($output['message'],0,1024),'html'=>$output['html']?1:0,'priority'=>$output['priority'],'sound'=>$output['sound']]]);curl_exec($ch);$code=(int)curl_getinfo($ch,CURLINFO_RESPONSE_CODE);curl_close($ch);return$code>=200&&$code<300?'sent':'failed:'.$code;
}
function deliver(array $output): string {
    if(!empty($output['destination_id'])){
        $q=db()->prepare('SELECT * FROM destinations WHERE id=? AND enabled=1');$q->execute([(int)$output['destination_id']]);$destination=$q->fetch(PDO::FETCH_ASSOC);
        if(!$destination)return'destination:not_available';$config=destination_config($destination);
        if($destination['type']==='pushover'){
            if(empty($config['app_key'])||empty($config['user_key']))return'pushover:not_configured';
            $ch=curl_init('https://api.pushover.net/1/messages.json');curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>10,CURLOPT_POSTFIELDS=>['token'=>$config['app_key'],'user'=>$config['user_key'],'title'=>substr($output['title'],0,250),'message'=>substr($output['message'],0,1024),'html'=>$output['html']?1:0,'priority'=>$output['priority'],'sound'=>$output['sound']]]);curl_exec($ch);$code=(int)curl_getinfo($ch,CURLINFO_RESPONSE_CODE);curl_close($ch);return$code>=200&&$code<300?'pushover:sent':'pushover:failed:'.$code;
        }
        $mapped=['smtp_host'=>'smtp_host','smtp_port'=>'smtp_port','smtp_security'=>'smtp_security','smtp_user'=>'smtp_user','smtp_password'=>'password','smtp_from'=>'sender_email','smtp_from_name'=>'sender_name'];$previous=[];foreach($mapped as$key=>$source){$previous[$key]=setting($key);if(isset($config[$source]))setv($key,$key==='smtp_password'?enc((string)$config[$source]):(string)$config[$source]);}$result=send_email((string)($config['recipient_email']??''),$output['title'],$output['message']);foreach($previous as$key=>$value)setv($key,$value);return'email:'.$result;
    }
    $push=send_pushover($output);if($push==='sent')return'pushover:sent';
    if(setting('email_fallback')==='1'){$email=send_email(setting('profile_email'),$output['title'],$output['message']);return'pushover:'.$push.',email:'.$email;}
    return'pushover:'.$push;
}
function destination_config(array $destination): array {
    $config=json_decode((string)$destination['configuration'],true)?:[];
    foreach(['app_key','user_key','password'] as $key)if(isset($config[$key]))$config[$key]=dec((string)$config[$key]);
    return $config;
}
function test_destination(array $destination): string {
    $config=destination_config($destination);
    if($destination['type']==='pushover'){
        if(empty($config['app_key'])||empty($config['user_key']))return'not_configured';
        $ch=curl_init('https://api.pushover.net/1/messages.json');curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>10,CURLOPT_POSTFIELDS=>['token'=>$config['app_key'],'user'=>$config['user_key'],'title'=>'NotifyRouter Destination Test','message'=>'Destination "'.$destination['name'].'" is configured correctly.']]);curl_exec($ch);$code=(int)curl_getinfo($ch,CURLINFO_RESPONSE_CODE);curl_close($ch);return$code>=200&&$code<300?'sent':'failed:'.$code;
    }
    $mapped=['smtp_host'=>'smtp_host','smtp_port'=>'smtp_port','smtp_security'=>'smtp_security','smtp_user'=>'smtp_user','smtp_password'=>'password','smtp_from'=>'sender_email','smtp_from_name'=>'sender_name'];$previous=[];foreach($mapped as $key=>$source){$previous[$key]=setting($key);if(isset($config[$source]))setv($key,$key==='smtp_password'?enc((string)$config[$source]):(string)$config[$source]);}
    $result=send_email((string)($config['recipient_email']??''),'NotifyRouter Destination Test','<b>Destination test successful.</b><br>'.h((string)$destination['name']));
    foreach($previous as $key=>$value)setv($key,$value);return$result;
}
function log_event(array $entry): void {
    $path=cfg()['event_log']??dirname(NOTIFYROUTER_CONFIG).'/notifyrouter-events.ndjson';
    file_put_contents($path,json_encode($entry,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)."\n",FILE_APPEND|LOCK_EX);
}
function session_start_secure(): void {
    if(session_status()===PHP_SESSION_ACTIVE)return;$secure=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')||strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO']??''))==='https';session_set_cookie_params(['httponly'=>true,'secure'=>$secure,'samesite'=>'Strict']);session_start();
}
function csrf(): string {session_start_secure();return$_SESSION['csrf']??=$_SESSION['csrf']=bin2hex(random_bytes(24));}
function require_csrf(): void {session_start_secure();if(!hash_equals($_SESSION['csrf']??'',(string)($_POST['csrf']??''))){http_response_code(403);exit('Invalid request token');}}
function h(string $value): string {return htmlspecialchars($value,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
function profile_url(): string {
    $custom=setting('profile_picture');if($custom!==''&&is_file(dirname(cfg()['database']).'/'.$custom))return'/profile-image';
    $email=strtolower(trim(setting('profile_email')));return'https://www.gravatar.com/avatar/'.md5($email).'?d=mp&s=96';
}
function page_start(string $title): void {
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'.h($title).'</title><link rel="icon" href="/assets/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/semantic-ui-css@2.5.0/semantic.min.css"><link rel="stylesheet" href="/assets/style.css"></head><body class="notifyrouter"><header class="ui borderless menu"><a href="/admin" class="header item brand-link"><img class="brand" src="/assets/logo.png" alt="NotifyRouter"></a>';
    if(!empty($_SESSION['admin']))echo'<nav class="right menu header-nav"><a class="item" href="/admin">Rules &amp; Outputs</a><a class="item settings-link" href="/admin/settings"><img class="nav-avatar" src="'.h(profile_url()).'" alt=""><span>Settings</span></a>'.(can_access_administration()?'<a class="item" href="/admin/administration">Administration</a>':'').'<div class="item"><form method="post" action="/admin"><input type="hidden" name="csrf" value="'.h(csrf()).'"><input type="hidden" name="action" value="logout"><button class="ui secondary button">Sign Out</button></form></div></nav>';
    echo'</header><main class="ui container">';
}
function page_end(): void {
    echo '</main><footer class="ui inverted vertical segment"><div class="ui container"><a href="'.NOTIFYROUTER_GITHUB.'" target="_blank" rel="noopener">NotifyRouter v'.NOTIFYROUTER_VERSION.'</a><span>© '.date('Y').' <a href="'.NOTIFYROUTER_AUTHOR.'" target="_blank" rel="noopener">Terry Rogers</a></span></div></footer><script>document.querySelectorAll("form:not(.inline)").forEach(e=>e.classList.add("ui","form"));document.querySelectorAll(".card").forEach(e=>e.classList.add("ui","segment"));document.querySelectorAll("table").forEach(e=>e.classList.add("ui","celled","compact","table"));document.querySelectorAll("button:not(.ui),a.button").forEach(e=>e.classList.add("ui","button"));document.querySelectorAll("button.danger").forEach(e=>e.classList.add("red"));document.querySelectorAll(".notice").forEach(e=>e.classList.add("ui","info","message"));document.querySelectorAll(".indicator,.status").forEach(e=>e.classList.add("ui","label"));</script></body></html>';
}
function require_admin(): void {session_start_secure();if(empty($_SESSION['admin'])){header('Location:/admin');exit;}}

if(defined('NOTIFYROUTER_BOOTSTRAP_ONLY')&&NOTIFYROUTER_BOOTSTRAP_ONLY)return;

$path=rtrim(parse_url($_SERVER['REQUEST_URI']??'/',PHP_URL_PATH),'/')?:'/';
if($path==='/profile-image'){
    $file=setting('profile_picture');$full=dirname(cfg()['database']).'/'.$file;
    if($file===''||!is_file($full)){http_response_code(404);exit;}
    $mime=(new finfo(FILEINFO_MIME_TYPE))->file($full);if(!in_array($mime,['image/jpeg','image/png','image/webp'],true)){http_response_code(404);exit;}
    header('Content-Type: '.$mime);header('Cache-Control: private, max-age=300');readfile($full);exit;
}
if($path==='/alarmid.php'||$path==='/webhook'){
    header('Content-Type:application/json');if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['status'=>'method_not_allowed']);exit;}
    $c=cfg();$supplied=$_SERVER['HTTP_X_SIGNAL_GATEWAY_TOKEN']??($_GET['token']??'');if($c['webhook_token']!==''&&!hash_equals($c['webhook_token'],(string)$supplied)){http_response_code(401);echo json_encode(['status'=>'unauthorized']);exit;}
    $raw=file_get_contents('php://input');$payload=json_decode($raw?:'',true);if(!is_array($payload)){http_response_code(400);echo json_encode(['status'=>'invalid_json']);exit;}
    [$vars,$outputs]=evaluate($payload);$statuses=array_map('deliver',$outputs);$status=$statuses?implode(';',$statuses):'no_match';$at=gmdate(DATE_ATOM);
    $q=db()->prepare('INSERT INTO events(received_at,payload,variables,matched_rules,status)VALUES(?,?,?,?,?)');$q->execute([$at,json_encode($payload),json_encode($vars),json_encode(array_column($outputs,'rule')),$status]);
    log_event(['received_at'=>$at,'remote'=>$_SERVER['REMOTE_ADDR']??'unknown','payload'=>$payload,'variables'=>$vars,'matched_rules'=>array_column($outputs,'rule'),'status'=>$status]);
    audit('Webhook Received','Matched '.count($outputs).' inbound rule(s); delivery status: '.$status,'Webhook');
    foreach($statuses as $deliveryStatus)audit('Message Sent','Delivery status: '.$deliveryStatus,'System');
    http_response_code(202);echo json_encode(['accepted'=>true,'matched_rules'=>array_column($outputs,'rule'),'status'=>$status]);exit;
}

session_start_secure();refresh_session_authorization();$setup=setting('admin_hash')==='';
if($path==='/admin/setup'){
    $ok=$setup&&hash_equals(cfg()['setup_token'],(string)($_GET['token']??$_POST['token']??''));$error='';
    if($_SERVER['REQUEST_METHOD']==='POST'&&$ok){$password=(string)($_POST['password']??'');if(strlen($password)<12)$error='Use at least 12 characters.';else{setv('admin_hash',password_hash($password,PASSWORD_DEFAULT));header('Location:/admin');exit;}}
    page_start('Admin Setup');echo'<section class="card narrow"><h1>Admin Setup</h1>';if(!$setup)echo'<p>Setup is complete. <a href="/admin">Sign In</a>.</p>';elseif(!$ok)echo'<p class="error">A valid one-time setup link is required.</p>';else echo($error?'<p class="error">'.h($error).'</p>':'').'<p>Choose an administrator password. This setup link is disabled afterwards.</p><form method="post"><input type="hidden" name="token" value="'.h(cfg()['setup_token']).'"><label>New Password<input type="password" name="password" minlength="12" required autofocus></label><button>Complete Setup</button></form>';echo'</section>';page_end();exit;
}
if($path==='/admin/forgot'){
    session_start_secure();$notice='';if($_SERVER['REQUEST_METHOD']==='POST'){$last=(int)($_SESSION['reset_requested_at']??0);if(time()-$last>=60){$_SESSION['reset_requested_at']=time();$channel=$_POST['channel']??'email';$account=trim((string)($_POST['account']??''));$q=db()->prepare('SELECT id,email,full_name,username FROM users WHERE enabled=1 AND (lower(username)=lower(?) OR lower(email)=lower(?)) LIMIT 1');$q->execute([$account,$account]);$recoveryUser=$q->fetch(PDO::FETCH_ASSOC);$recipient=$recoveryUser['email']??setting('profile_email');$token=bin2hex(random_bytes(32));$q=db()->prepare('INSERT INTO reset_tokens(token_hash,expires_at,user_id)VALUES(?,?,?)');$q->execute([hash('sha256',$token),time()+1800,$recoveryUser['id']??null]);$scheme=((!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')||strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO']??''))==='https')?'https':'http';$host=preg_replace('/[^A-Za-z0-9.:-]/','',(string)($_SERVER['HTTP_HOST']??'localhost'));$link=$scheme.'://'.$host.'/admin/reset?token='.$token;$message='<b>Password reset requested.</b><br><a href="'.$link.'">Reset Password</a><br>This link expires in 30 minutes.';$result=$channel==='pushover'?send_pushover(['title'=>'NotifyRouter Password Reset','message'=>$message,'html'=>true,'priority'=>0,'sound'=>'pushover']):send_email($recipient,'NotifyRouter Password Reset',$message);if($result!=='sent')db()->prepare('DELETE FROM reset_tokens WHERE token_hash=?')->execute([hash('sha256',$token)]);audit('Password Reset Request','Recovery channel: '.$channel,'Anonymous');}$notice='If that account and recovery channel are configured, a reset link has been sent.';}
    page_start('Forgot Password');echo'<section class="card narrow"><h1>Forgot Password</h1>'.($notice?'<p class="status">'.h($notice).'</p>':'').'<p>Send a single-use link that expires after 30 minutes.</p><form method="post"><label>Username Or Email Address<input name="account" required></label><label>Recovery Channel<select name="channel"><option value="email">Email</option><option value="pushover">Pushover</option></select></label><button>Send Reset Link</button></form><p><a href="/admin">Back To Sign In</a></p></section>';page_end();exit;
}
if($path==='/admin/reset'){
    $token=(string)($_GET['token']??$_POST['token']??'');$q=db()->prepare('SELECT id,user_id FROM reset_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>=? ORDER BY id DESC LIMIT 1');$q->execute([hash('sha256',$token),time()]);$reset=$q->fetch(PDO::FETCH_ASSOC);$id=$reset['id']??0;$error='';
    if($_SERVER['REQUEST_METHOD']==='POST'&&$id){$password=(string)($_POST['password']??'');if(strlen($password)<12)$error='Use at least 12 characters.';else{if(!empty($reset['user_id']))db()->prepare('UPDATE users SET password_hash=?,updated_at=? WHERE id=?')->execute([password_hash($password,PASSWORD_DEFAULT),gmdate(DATE_ATOM),(int)$reset['user_id']]);else setv('admin_hash',password_hash($password,PASSWORD_DEFAULT));db()->prepare('UPDATE reset_tokens SET used_at=? WHERE id=?')->execute([time(),$id]);audit('Password Change','Password changed through a reset link','Anonymous');session_destroy();header('Location:/admin');exit;}}
    page_start('Reset Password');echo'<section class="card narrow"><h1>Reset Password</h1>';if(!$id)echo'<p class="error">This reset link is invalid or expired.</p>';else echo($error?'<p class="error">'.h($error).'</p>':'').'<form method="post"><input type="hidden" name="token" value="'.h($token).'"><label>New Password<input type="password" name="password" minlength="12" required></label><button>Change Password</button></form>';echo'</section>';page_end();exit;
}
if($setup){header('Location:/admin/setup');exit;}
if(empty($_SESSION['admin'])){
    $error='';if($_SERVER['REQUEST_METHOD']==='POST'){$username=trim((string)($_POST['username']??'admin'));$password=(string)($_POST['password']??'');$q=db()->prepare('SELECT u.*,r.name role_name FROM users u JOIN roles r ON r.id=u.role_id WHERE lower(u.username)=lower(?) LIMIT 1');$q->execute([$username]);$user=$q->fetch(PDO::FETCH_ASSOC);$valid=$user&&$user['enabled']&&password_verify($password,$user['password_hash']);$needsEnrollment=false;if($valid&&setting('enforce_2fa')==='1'){if(empty($user['two_factor_secret']))$needsEnrollment=true;else$valid=totp_valid(dec((string)$user['two_factor_secret']),(string)($_POST['otp']??''));}$legacy=strtolower($username)==='admin'&&password_verify($password,setting('admin_hash'));if($valid||$legacy){session_regenerate_id(true);$_SESSION['admin']=true;$_SESSION['csrf']=bin2hex(random_bytes(24));if($valid){$_SESSION['user_id']=(int)$user['id'];$_SESSION['user_name']=$user['full_name'];$_SESSION['permissions']=role_permissions((int)$user['role_id']);if($needsEnrollment)$_SESSION['must_register_2fa']=true;}else{$_SESSION['legacy_admin']=true;$_SESSION['user_name']='Administrator';$_SESSION['permissions']=PERMISSIONS;}audit('Login','Successful sign in');header('Location:'.($needsEnrollment?'/admin/settings':'/admin'));exit;}$error='Incorrect username, password, or verification code.';audit('Login','Failed sign in for username '.$username,'Anonymous');}
    page_start('Admin Sign In');echo'<section class="card narrow"><h1>Admin Sign In</h1>'.($error?'<p class="error">'.h($error).'</p>':'').'<form method="post"><label>Username<input name="username" value="admin" required autofocus autocomplete="username"></label><label>Password<input type="password" name="password" required autocomplete="current-password"></label><label>2FA Verification Code <span>Required when 2FA enforcement is enabled.</span><input name="otp" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code"></label><button>Sign In</button></form><p><a href="/admin/forgot">Forgot Password?</a></p></section>';page_end();exit;
}
if(!empty($_SESSION['must_register_2fa'])&&$path!=='/admin/settings'){
    if($_SERVER['REQUEST_METHOD']==='POST'&&($_POST['action']??'')==='logout'){require_csrf();audit('Logout','Successful sign out');session_destroy();header('Location:/admin');exit;}
    header('Location:/admin/settings');exit;
}
if($path==='/admin/inspect'){require_csrf();header('Content-Type:application/json');$payload=json_decode((string)($_POST['payload']??''),true);if(!is_array($payload)){http_response_code(400);echo json_encode(['error'=>'Invalid JSON']);exit;}[$vars,$outputs]=evaluate($payload);echo json_encode(['variables'=>$vars,'outputs'=>$outputs],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);exit;}
$message='';
if($_SERVER['REQUEST_METHOD']==='POST'){
    require_csrf();$action=$_POST['action']??'';
    if($action==='logout'){audit('Logout','Successful sign out');session_destroy();header('Location:/admin');exit;}
    if($action==='settings'){require_permission('Administrator');foreach(['app_name','smtp_host','smtp_port','smtp_security','smtp_user','smtp_from','smtp_from_name','smtp_status_url','profile_email']as$key)setv($key,trim((string)($_POST[$key]??setting($key))));setv('email_fallback',isset($_POST['email_fallback'])?'1':'0');foreach(['pushover_token','pushover_user','smtp_password']as$key)if((string)($_POST[$key]??'')!=='')setv($key,enc((string)$_POST[$key]));audit('Configuration Change','Legacy delivery settings updated');$message='Settings saved.';}
    if($action==='test_pushover'){require_permission('Administrator');$message='Pushover test: '.send_pushover(['title'=>'NotifyRouter Test','message'=>'<b>Test successful.</b> Pushover settings are working.','html'=>true,'priority'=>0,'sound'=>'pushover']);audit('Message Sent',$message);}
    if($action==='test_email'){require_permission('Administrator');$message='Email test: '.send_email(setting('profile_email'),'NotifyRouter Test','<b>Test successful.</b> Email settings are working.');audit('Message Sent',$message);}
    if($action==='clear_events'){require_permission('Clear Recent Events');db()->exec('DELETE FROM events');audit('Configuration Change','Recent events cleared');$message='Recent events cleared.';}
    if($action==='clear_log'){require_permission('Clear Payload Log');$log=cfg()['event_log']??dirname(NOTIFYROUTER_CONFIG).'/notifyrouter-events.ndjson';file_put_contents($log,'',LOCK_EX);audit('Configuration Change','Payload log cleared');$message='Captured payload log cleared.';}
    if($action==='delete_rule'){require_permission('Manage Inbound Rules');db()->prepare('DELETE FROM rules WHERE id=?')->execute([(int)$_POST['id']]);audit('Configuration Change','Inbound rule deleted: ID '.(int)$_POST['id']);$message='Inbound rule deleted.';}
    if($action==='rule'){require_permission('Manage Inbound Rules');$conditions=json_decode((string)($_POST['conditions']??'[]'),true);if(!is_array($conditions))$message='Conditions must be valid JSON.';else{$id=(int)($_POST['id']??0);$values=[(string)$_POST['name'],isset($_POST['enabled'])?1:0,(int)$_POST['priority'],($_POST['match_mode']??'all')==='any'?'any':'all',json_encode($conditions),isset($_POST['stop_processing'])?1:0,(int)($_POST['template_id']??0)?:null];if($id){$q=db()->prepare('UPDATE rules SET name=?,enabled=?,priority=?,match_mode=?,conditions=?,stop_processing=?,template_id=? WHERE id=?');$q->execute([...$values,$id]);}else{$q=db()->prepare('INSERT INTO rules(name,enabled,priority,match_mode,conditions,title_template,message_template,html,pushover_priority,sound,stop_processing,template_id)VALUES(?,?,?,?,?,\'\',\'\',1,0,\'pushover\',?,?)');$q->execute($values);}audit('Configuration Change','Inbound rule saved: '.$values[0]);$message='Inbound rule saved.';}}
    if($action==='save_template'){require_permission('Manage Outbound Templates');$id=(int)($_POST['id']??0);$values=[trim((string)($_POST['name']??'')),trim((string)($_POST['description']??'')),(int)($_POST['destination_id']??0)?:null,(string)($_POST['title_template']??''),(string)($_POST['message_template']??''),isset($_POST['html'])?1:0,gmdate(DATE_ATOM)];if($id){$q=db()->prepare('UPDATE outbound_templates SET name=?,description=?,destination_id=?,title_template=?,message_template=?,html=?,updated_at=? WHERE id=?');$q->execute([...$values,$id]);}else{$q=db()->prepare('INSERT INTO outbound_templates(name,description,destination_id,title_template,message_template,html,created_at,updated_at)VALUES(?,?,?,?,?,?,?,?)');$q->execute([...$values,$values[6]]);}audit('Configuration Change','Outbound template saved: '.$values[0]);$message='Outbound template saved.';}
    if($action==='delete_template'){require_permission('Manage Outbound Templates');$id=(int)$_POST['id'];$used=(int)db()->query('SELECT COUNT(*) FROM rules WHERE template_id='.$id)->fetchColumn();if($used)$message='Templates assigned to inbound rules cannot be deleted.';else{db()->prepare('DELETE FROM outbound_templates WHERE id=?')->execute([$id]);audit('Configuration Change','Outbound template deleted: ID '.$id);$message='Outbound template deleted.';}}
    if($action==='profile'){$email=trim((string)($_POST['profile_email']??''));setv('profile_email',$email);$newPassword=(string)($_POST['new_password']??'');if($newPassword!==''&&strlen($newPassword)<12)$message='Password must be at least 12 characters.';else{if(!empty($_SESSION['user_id'])){$params=[$email,gmdate(DATE_ATOM)];$sql='UPDATE users SET email=?,updated_at=?';if($newPassword!==''){$sql.=',password_hash=?';$params[]=password_hash($newPassword,PASSWORD_DEFAULT);}$sql.=' WHERE id=?';$params[]=(int)$_SESSION['user_id'];db()->prepare($sql)->execute($params);}elseif($newPassword!=='')setv('admin_hash',password_hash($newPassword,PASSWORD_DEFAULT));audit($newPassword!==''?'Password Change':'Configuration Change',$newPassword!==''?'Profile and password updated':'Profile updated');$message=$newPassword!==''?'Profile and password updated.':'Profile updated.';}if(isset($_FILES['profile_picture'])&&$_FILES['profile_picture']['error']===UPLOAD_ERR_OK&&$_FILES['profile_picture']['size']<=2097152){$mime=(new finfo(FILEINFO_MIME_TYPE))->file($_FILES['profile_picture']['tmp_name']);$ext=['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'][$mime]??'';if($ext!==''){$relative='profile.'.$ext;$target=dirname(cfg()['database']).'/'.$relative;if(move_uploaded_file($_FILES['profile_picture']['tmp_name'],$target)){chmod($target,0640);setv('profile_picture',$relative);}}}}
    if($action==='start_2fa'&&!empty($_SESSION['user_id'])){$_SESSION['pending_2fa_secret']=base32_encode_secret(random_bytes(20));$message='Add the displayed secret to your authenticator, then verify a code.';}
    if($action==='confirm_2fa'&&!empty($_SESSION['user_id'])){$secret=(string)($_SESSION['pending_2fa_secret']??'');if($secret!==''&&totp_valid($secret,(string)($_POST['otp']??''))){db()->prepare('UPDATE users SET two_factor_secret=?,updated_at=? WHERE id=?')->execute([enc($secret),gmdate(DATE_ATOM),(int)$_SESSION['user_id']]);unset($_SESSION['pending_2fa_secret'],$_SESSION['must_register_2fa']);audit('Configuration Change','2FA registered for current user');$message='2FA registration completed.';}else$message='The verification code was not valid.';}
    if($action==='disable_2fa'&&!empty($_SESSION['user_id'])){db()->prepare('UPDATE users SET two_factor_secret=NULL,updated_at=? WHERE id=?')->execute([gmdate(DATE_ATOM),(int)$_SESSION['user_id']]);unset($_SESSION['pending_2fa_secret']);audit('Configuration Change','2FA disabled for current user');$message='2FA disabled.';}
    if($action==='save_user'){
        require_permission('Administrator');$id=(int)($_POST['id']??0);$username=trim((string)($_POST['username']??''));$fullName=trim((string)($_POST['full_name']??''));$email=trim((string)($_POST['email']??''));$roleId=(int)($_POST['role_id']??0);$enabled=isset($_POST['enabled'])?1:0;
        if(!preg_match('/^[A-Za-z0-9_.-]{3,64}$/',$username)||$fullName===''||!filter_var($email,FILTER_VALIDATE_EMAIL)||$roleId<1){$message='Enter a valid username, full name, email address, and role.';}else{
            $password=bin2hex(random_bytes(8));$now=gmdate(DATE_ATOM);
            if($id){$q=db()->prepare('UPDATE users SET username=?,full_name=?,email=?,role_id=?,enabled=?,updated_at=? WHERE id=?');$q->execute([$username,$fullName,$email,$roleId,$enabled,$now,$id]);audit('Configuration Change','User updated: '.$username);$message='User saved.';}
            else{$q=db()->prepare('INSERT INTO users(username,full_name,email,password_hash,role_id,enabled,created_at,updated_at)VALUES(?,?,?,?,?,?,?,?)');$q->execute([$username,$fullName,$email,password_hash($password,PASSWORD_DEFAULT),$roleId,$enabled,$now,$now]);$id=(int)db()->lastInsertId();audit('Configuration Change','User created: '.$username);if(isset($_POST['email_reset'])){$token=bin2hex(random_bytes(32));db()->prepare('INSERT INTO reset_tokens(token_hash,expires_at,user_id)VALUES(?,?,?)')->execute([hash('sha256',$token),time()+86400,$id]);$scheme=!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off'?'https':'http';$host=preg_replace('/[^A-Za-z0-9.:-]/','',(string)($_SERVER['HTTP_HOST']??'localhost'));$link=$scheme.'://'.$host.'/admin/reset?token='.$token;$subject=setting('welcome_subject','Welcome To NotifyRouter');$body=str_replace(['{{ full_name }}','{{ username }}','{{ reset_link }}'],[h($fullName),h($username),h($link)],setting('welcome_body','Hello {{ full_name }},<br><br>Your NotifyRouter username is <b>{{ username }}</b>.<br><a href="{{ reset_link }}">Set Your Password</a>'));$result=send_email($email,$subject,$body);$message='User created; welcome email status: '.$result;}else{$_SESSION['generated_password']=$password;$message='User created. Copy the generated password shown below.';}}
        }
    }
    if($action==='delete_user'){require_permission('Administrator');$id=(int)$_POST['id'];if($id===(int)($_SESSION['user_id']??0))$message='You cannot delete your own account.';else{db()->prepare('DELETE FROM users WHERE id=?')->execute([$id]);audit('Configuration Change','User deleted: ID '.$id);$message='User deleted.';}}
    if($action==='save_role'){require_permission('Administrator');$id=(int)($_POST['id']??0);$name=trim((string)($_POST['name']??''));$selected=array_values(array_intersect(PERMISSIONS,$_POST['permissions']??[]));if($name==='')$message='Role name is required.';else{if($id){$built=(int)db()->query('SELECT built_in FROM roles WHERE id='.$id)->fetchColumn();if($built)$message='Built-in roles cannot be renamed or changed.';else{db()->prepare('UPDATE roles SET name=? WHERE id=?')->execute([$name,$id]);}}else{db()->prepare('INSERT INTO roles(name,built_in)VALUES(?,0)')->execute([$name]);$id=(int)db()->lastInsertId();}if($message===''){db()->prepare('DELETE FROM role_permissions WHERE role_id=?')->execute([$id]);$q=db()->prepare('INSERT INTO role_permissions(role_id,permission)VALUES(?,?)');foreach($selected as$permission)$q->execute([$id,$permission]);audit('Configuration Change','Role saved: '.$name);$message='Role saved.';}}}
    if($action==='delete_role'){require_permission('Administrator');$id=(int)$_POST['id'];$q=db()->prepare('SELECT built_in,(SELECT COUNT(*) FROM users WHERE role_id=roles.id) user_count FROM roles WHERE id=?');$q->execute([$id]);$role=$q->fetch(PDO::FETCH_ASSOC);if(!$role||$role['built_in']||$role['user_count'])$message='Built-in or assigned roles cannot be deleted.';else{db()->prepare('DELETE FROM roles WHERE id=?')->execute([$id]);audit('Configuration Change','Role deleted: ID '.$id);$message='Role deleted.';}}
    if($action==='save_destination'){require_permission('Administrator');$id=(int)($_POST['id']??0);$type=($_POST['type']??'pushover')==='email'?'email':'pushover';$existing=[];if($id){$q=db()->prepare('SELECT configuration FROM destinations WHERE id=?');$q->execute([$id]);$existing=json_decode((string)$q->fetchColumn(),true)?:[];}$config=$type==='pushover'?['user_key'=>(string)($existing['user_key']??''),'app_key'=>(string)($existing['app_key']??'')]:['smtp_host'=>trim((string)($_POST['smtp_host']??'')),'smtp_port'=>(string)($_POST['smtp_port']??'587'),'smtp_security'=>(string)($_POST['smtp_security']??'starttls'),'smtp_user'=>trim((string)($_POST['smtp_user']??'')),'password'=>(string)($existing['password']??''),'sender_name'=>trim((string)($_POST['sender_name']??'')),'sender_email'=>trim((string)($_POST['sender_email']??'')),'recipient_name'=>trim((string)($_POST['recipient_name']??'')),'recipient_email'=>trim((string)($_POST['recipient_email']??''))];if($type==='pushover'){if((string)($_POST['user_key']??'')!=='')$config['user_key']=enc((string)$_POST['user_key']);if((string)($_POST['app_key']??'')!=='')$config['app_key']=enc((string)$_POST['app_key']);}elseif((string)($_POST['password']??'')!=='')$config['password']=enc((string)$_POST['password']);$values=[trim((string)($_POST['name']??'')),trim((string)($_POST['description']??'')),$type,json_encode($config),isset($_POST['enabled'])?1:0,gmdate(DATE_ATOM)];if($id){$q=db()->prepare('UPDATE destinations SET name=?,description=?,type=?,configuration=?,enabled=?,updated_at=? WHERE id=?');$q->execute([...$values,$id]);}else{$q=db()->prepare('INSERT INTO destinations(name,description,type,configuration,enabled,created_at,updated_at)VALUES(?,?,?,?,?,?,?)');$q->execute([$values[0],$values[1],$values[2],$values[3],$values[4],$values[5],$values[5]]);}audit('Configuration Change','Destination saved: '.$values[0]);$message='Destination saved.';}
    if($action==='delete_destination'){require_permission('Administrator');$id=(int)$_POST['id'];db()->prepare('DELETE FROM destinations WHERE id=?')->execute([$id]);audit('Configuration Change','Destination deleted: ID '.$id);$message='Destination deleted.';}
    if($action==='test_destination'){require_permission('Administrator');$id=(int)$_POST['id'];$q=db()->prepare('SELECT * FROM destinations WHERE id=?');$q->execute([$id]);$destination=$q->fetch(PDO::FETCH_ASSOC);$result=$destination?test_destination($destination):'not_found';audit('Message Sent','Destination test '.$result.': ID '.$id);$message='Destination test: '.$result;}
    if($action==='service_health'){require_permission('Administrator');$pushCount=(int)db()->query("SELECT COUNT(*) FROM destinations WHERE type='pushover' AND enabled=1")->fetchColumn();$emailCount=(int)db()->query("SELECT COUNT(*) FROM destinations WHERE type='email' AND enabled=1")->fetchColumn();setv('pushover_operational',isset($_POST['pushover_operational'])&&$pushCount?'1':'0');setv('email_operational',isset($_POST['email_operational'])&&$emailCount?'1':'0');setv('pushover_status_rss',trim((string)($_POST['pushover_status_rss']??'')));setv('smtp_test_host',trim((string)($_POST['smtp_test_host']??'')));setv('smtp_test_port',(string)(int)($_POST['smtp_test_port']??587));setv('smtp_status_url',trim((string)($_POST['smtp_status_url']??'')));audit('Configuration Change','Service health settings updated');$message='Service health settings saved.'.(!$pushCount||!$emailCount?' A service without an enabled destination remains disabled.':'');}
    if($action==='security'){require_permission('Administrator');setv('support_email',trim((string)($_POST['support_email']??'')));$unenrolled=(int)db()->query("SELECT COUNT(*) FROM users WHERE enabled=1 AND (two_factor_secret IS NULL OR two_factor_secret='')")->fetchColumn();if(isset($_POST['enforce_2fa'])&&$unenrolled)$message='2FA cannot be enforced until every enabled user is registered.';else{setv('enforce_2fa',isset($_POST['enforce_2fa'])?'1':'0');$message='Security settings saved.';}audit('Configuration Change','Security settings updated');}
    if($action==='email_global'){require_permission('Administrator');foreach(['smtp_host','smtp_port','smtp_security','smtp_user','smtp_from','smtp_from_name','email_message_type','email_footer','welcome_subject','welcome_body','reset_subject','reset_body'] as$key)setv($key,trim((string)($_POST[$key]??'')));if((string)($_POST['smtp_password']??'')!=='')setv('smtp_password',enc((string)$_POST['smtp_password']));audit('Configuration Change','Global email settings updated');$message='Email settings and templates saved.';}
    if($action==='test_email_template'){require_permission('Administrator');$userId=(int)($_POST['user_id']??0);$template=($_POST['template']??'welcome')==='reset'?'reset':'welcome';$q=db()->prepare('SELECT full_name,username,email FROM users WHERE id=?');$q->execute([$userId]);$u=$q->fetch(PDO::FETCH_ASSOC);if($u){$subject=setting($template.'_subject',$template==='welcome'?'Welcome To NotifyRouter':'NotifyRouter Password Reset');$body=setting($template.'_body','Hello {{ full_name }}');$body=str_replace(['{{ full_name }}','{{ username }}','{{ reset_link }}'],[h($u['full_name']),h($u['username']),'[Test Reset Link]'],$body);$result=send_email($u['email'],$subject,$body);audit('Message Sent','Email template test '.$result.': '.$template);$message='Template test: '.$result;}else$message='Select a user.';}
}
$adminPrefix='/admin/administration';
if($path===$adminPrefix||str_starts_with($path,$adminPrefix.'/')){
    require_permission('Read-only Administrator');
    $section=trim(substr($path,strlen($adminPrefix)),'/')?:'overview';
    $allowedSections=['overview','users','roles','service-health','destinations','security','email','log'];
    if(!in_array($section,$allowedSections,true)){http_response_code(404);exit('Not found');}
    require __DIR__.'/admin-console.php';exit;
}
$rules=db()->query('SELECT r.*,t.name template_name FROM rules r LEFT JOIN outbound_templates t ON t.id=r.template_id ORDER BY r.priority,r.id')->fetchAll(PDO::FETCH_ASSOC);$templates=db()->query('SELECT t.*,d.name destination_name,d.type destination_type FROM outbound_templates t LEFT JOIN destinations d ON d.id=t.destination_id ORDER BY t.name')->fetchAll(PDO::FETCH_ASSOC);$destinations=db()->query('SELECT id,name,type FROM destinations WHERE enabled=1 ORDER BY type,name')->fetchAll(PDO::FETCH_ASSOC);$events=can('View Recent Events')?db()->query('SELECT * FROM events ORDER BY id DESC LIMIT 50')->fetchAll(PDO::FETCH_ASSOC):[];$pushStatus=pushover_status();$mailStatus=smtp_probe();$logEntries=[];$log=cfg()['event_log']??dirname(NOTIFYROUTER_CONFIG).'/notifyrouter-events.ndjson';if(can('View Payload Log')&&is_file($log)){$lines=file($log,FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES)?:[];foreach(array_slice(array_reverse($lines),0,50)as$line){$item=json_decode($line,true);if(is_array($item))$logEntries[]=$item;}}
page_start('NotifyRouter Admin');
?>
<div class="top"><div><h1>Rules &amp; Outputs</h1><p>Match any incoming payload item and use it in a message template.</p></div></div>
<?php if($message):?><p class="notice"><?=h($message)?></p><?php endif;?>
<?php if($path==='/admin/settings'):?>
<section class="card"><h2>Profile Settings</h2><form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="profile"><label>Email Address<input type="email" name="profile_email" value="<?=h(setting('profile_email'))?>" required></label><label>Profile Picture <span>JPEG, PNG, or WebP; defaults to Gravatar.</span><input type="file" name="profile_picture" accept="image/jpeg,image/png,image/webp"></label><label>New Password <span>Leave blank to keep the current password.</span><input type="password" name="new_password" minlength="12"></label><button>Save Profile</button></form></section><?php if(!empty($_SESSION['user_id'])):$q=db()->prepare('SELECT two_factor_secret FROM users WHERE id=?');$q->execute([(int)$_SESSION['user_id']]);$has2fa=(string)$q->fetchColumn()!=='';?><section class="card"><h2>Two-Factor Authentication</h2><p><?=$has2fa?'2FA is registered for this account.':'Register this account before an administrator enables global enforcement.'?></p><?php if(isset($_SESSION['pending_2fa_secret'])):?><div class="notice secret-once"><strong>Authenticator Secret</strong><code><?=h((string)$_SESSION['pending_2fa_secret'])?></code><span>Enter this secret in an authenticator app, then verify the current six-digit code.</span></div><form method="post"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="confirm_2fa"><label>Verification Code<input name="otp" inputmode="numeric" pattern="[0-9]{6}" required></label><button>Verify And Enable 2FA</button></form><?php elseif(!$has2fa):?><form method="post"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="start_2fa"><button>Start 2FA Registration</button></form><?php else:?><form method="post" onsubmit="return confirm('Disable 2FA for your account?')"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="disable_2fa"><button class="danger">Disable 2FA</button></form><?php endif;?></section><?php endif;?><p><a href="/admin">Back To Dashboard</a></p>
<?php else:?>
<?php if(can('Administrator')):?><section class="grid services">
<article class="card"><div class="tilehead"><h2>Pushover Settings</h2><span class="indicator <?=$pushStatus['level']?>"><?=$pushStatus['label']?></span></div><p class="service-note"><?=h($pushStatus['note'])?></p><form method="post"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="settings"><label>Application API Token<input type="password" name="pushover_token" placeholder="Leave blank to keep current value"></label><label>User Or Group Key<input type="password" name="pushover_user" placeholder="Leave blank to keep current value"></label><button>Save Settings</button></form><form method="post" class="testform"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="test_pushover"><button class="secondary">Test Pushover</button></form></article>
<article class="card"><div class="tilehead"><h2>Email Settings</h2><span class="indicator <?=$mailStatus['level']?>"><?=$mailStatus['label']?></span></div><p class="service-note"><?=h($mailStatus['note'])?></p><form method="post"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="settings"><label>SMTP Host<input name="smtp_host" value="<?=h(setting('smtp_host'))?>"></label><div class="fields"><label>Port<input type="number" name="smtp_port" value="<?=h(setting('smtp_port','587'))?>"></label><label>Security<select name="smtp_security"><option value="starttls">STARTTLS</option><option value="ssl" <?=setting('smtp_security')==='ssl'?'selected':''?>>TLS/SSL</option><option value="none" <?=setting('smtp_security')==='none'?'selected':''?>>None</option></select></label></div><label>Username<input name="smtp_user" value="<?=h(setting('smtp_user'))?>"></label><label>Password<input type="password" name="smtp_password" placeholder="Leave blank to keep current value"></label><label>From Address<input type="email" name="smtp_from" value="<?=h(setting('smtp_from'))?>"></label><label>From Name<input name="smtp_from_name" value="<?=h(setting('smtp_from_name','NotifyRouter'))?>"></label><label>Provider Status Page URL<input type="url" name="smtp_status_url" value="<?=h(setting('smtp_status_url'))?>"></label><label>Recovery Email<input type="email" name="profile_email" value="<?=h(setting('profile_email'))?>"></label><label class="check"><input type="checkbox" name="email_fallback" <?=setting('email_fallback')==='1'?'checked':''?>> Use Email If Pushover Is Unavailable</label><button>Save Settings</button></form><form method="post" class="testform"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="test_email"><button class="secondary">Test Email</button></form></article>
</section><?php endif;?>
<section class="card full"><h2>Payload Inspector</h2><p>Paste a payload to list every flattened variable and preview matched outputs without sending.</p><form method="post" action="/admin/inspect" target="inspect-result"><input type="hidden" name="csrf" value="<?=csrf()?>"><textarea name="payload" rows="10">{"events":[{"alert_key":"CLIENT_CONNECTED","scope":{"site_id":"example"}}]}</textarea><button>Inspect Payload</button></form></section>
<?php if(can('Manage Outbound Templates')):?><section class="card"><h2>Create Outbound Template</h2><p>Templates are separate from inbound match rules and select one configured destination.</p><form method="post" class="form-grid"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="save_template"><label>Template Name<input name="name" required></label><label>Destination<select name="destination_id" required><option value="">Select A Destination</option><?php foreach($destinations as$d):?><option value="<?=$d['id']?>"><?=h($d['name'].' · '.ucfirst($d['type']))?></option><?php endforeach;?></select></label><label class="wide">Short Description<input name="description"></label><label class="wide">Title Template<input name="title_template" value="Event: {{ events.0.alert_key }}"></label><label class="wide">Message Template<textarea name="message_template" rows="4">Event &lt;b&gt;{{ events.0.alert_key }}&lt;/b&gt; occurred at site {{ events.0.scope.site_id }}.</textarea></label><label class="check wide"><input type="checkbox" name="html" checked> Enable HTML Formatting</label><div class="wide"><button>Save Outbound Template</button></div></form></section>
<section class="card"><h2>Outbound Templates</h2><div class="table"><table><thead><tr><th>ID</th><th>Name</th><th>Destination</th><th>Type</th><th>Actions</th></tr></thead><tbody><?php foreach($templates as$t):?><tr><td><?=$t['id']?></td><td><?=h($t['name'])?></td><td><?=h((string)($t['destination_name']??'Not Assigned'))?></td><td><?=h(ucfirst((string)($t['destination_type']??'Unknown')))?></td><td><form method="post" class="inline" onsubmit="return confirm('Delete this outbound template?')"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="delete_template"><input type="hidden" name="id" value="<?=$t['id']?>"><button class="danger small">Delete</button></form></td></tr><?php endforeach;?><?php if(!$templates):?><tr><td colspan="5">No Outbound Templates Yet</td></tr><?php endif;?></tbody></table></div></section><?php endif;?>
<?php if(can('Manage Inbound Rules')):?><section class="card"><h2>Create Or Update Inbound Rule</h2><form method="post" class="ruleform"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="rule"><label>Rule ID <span>Leave blank to create</span><input name="id" type="number"></label><label>Rule Name<input name="name" required></label><label>Priority<input name="priority" type="number" value="100"></label><label>Match Mode<select name="match_mode"><option value="all">All Conditions</option><option value="any">Any Condition</option></select></label><label class="wide">Conditions JSON<textarea name="conditions" rows="4">[{"path":"events.*.alert_key","operator":"equals","value":"CLIENT_CONNECTED"}]</textarea></label><label class="wide">Outbound Template<select name="template_id" required><option value="">Select An Outbound Template</option><?php foreach($templates as$t):?><option value="<?=$t['id']?>"><?=h($t['name'])?></option><?php endforeach;?></select></label><label class="check"><input type="checkbox" name="enabled" checked> Enabled</label><label class="check"><input type="checkbox" name="stop_processing"> Stop After Match</label><button>Save Inbound Rule</button></form></section><?php endif;?>
<section class="card"><h2>Inbound Rules</h2><div class="table"><table><thead><tr><th>ID</th><th>Priority</th><th>Name</th><th>Conditions</th><th>Outbound Template</th><th>Enabled</th><th>Actions</th></tr></thead><tbody><?php foreach($rules as$r):?><tr><td><?=$r['id']?></td><td><?=$r['priority']?></td><td><?=h($r['name'])?></td><td><code><?=h($r['conditions'])?></code></td><td><?=h((string)($r['template_name']??'Not Assigned'))?></td><td><?=$r['enabled']?'Yes':'No'?></td><td><?php if(can('Manage Inbound Rules')):?><form method="post" class="inline" onsubmit="return confirm('Delete this inbound rule?')"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="delete_rule"><input type="hidden" name="id" value="<?=$r['id']?>"><button class="danger small">Delete</button></form><?php endif;?></td></tr><?php endforeach;?><?php if(!$rules):?><tr><td colspan="7">No Inbound Rules Yet</td></tr><?php endif;?></tbody></table></div></section>
<?php if(can('View Recent Events')):?><section class="card"><div class="tilehead"><h2>Recent Events</h2><?php if(can('Clear Recent Events')):?><form method="post" onsubmit="return confirm('Clear all recent events?')"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="clear_events"><button class="danger">Clear Recent Events</button></form><?php endif;?></div><div class="eventlist"><?php foreach($events as$event):$payload=json_decode($event['payload'],true);?><details><summary><strong><?=h($event['received_at'])?></strong> · <?=h($event['status'])?> · <?=h(implode(', ',json_decode($event['matched_rules'],true)?:['No Rule']))?></summary><pre><?=h(json_encode($payload,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE))?></pre></details><?php endforeach;?><?php if(!$events):?><p>No Events Captured.</p><?php endif;?></div></section><?php endif;?>
<?php if(can('View Payload Log')):?><section class="card"><div class="tilehead"><div><h2>Payload Log</h2><p>Integrated diagnostic log: <code>notifyrouter-events.ndjson</code></p></div><?php if(can('Clear Payload Log')):?><form method="post" onsubmit="return confirm('Clear the payload log?')"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="clear_log"><button class="danger">Clear Payload Log</button></form><?php endif;?></div><div class="eventlist"><?php foreach($logEntries as$entry):?><details><summary><strong><?=h((string)($entry['received_at']??'Unknown time'))?></strong> · <?=h((string)($entry['status']??'Unknown'))?></summary><pre><?=h(json_encode($entry,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE))?></pre></details><?php endforeach;?><?php if(!$logEntries):?><p>No Diagnostic Payloads Captured.</p><?php endif;?></div></section><?php endif;?>
<?php endif; page_end();
