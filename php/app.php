<?php
declare(strict_types=1);

const CSG_VERSION = '0.2.0';
const CSG_CONFIG = '/srv/www/.signal-gateway/config.php';
const CSG_GITHUB = 'https://github.com/terryrogers/cloudhub-signal-gateway';
const CSG_AUTHOR = 'https://www.terryrogers.me';

function cfg(): array {
    $config = require CSG_CONFIG;
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
      CREATE TABLE IF NOT EXISTS reset_tokens(id INTEGER PRIMARY KEY AUTOINCREMENT,token_hash TEXT NOT NULL,expires_at INTEGER NOT NULL,used_at INTEGER)");
    return $db;
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
    foreach(db()->query('SELECT * FROM rules WHERE enabled=1 ORDER BY priority,id')->fetchAll(PDO::FETCH_ASSOC) as $rule) {
        $conditions=json_decode($rule['conditions'],true)?:[]; $results=array_map(fn($c)=>condition_matches($c,$vars),$conditions);
        $matched=$rule['match_mode']==='any'?in_array(true,$results,true):!in_array(false,$results,true);
        if(!$matched) continue;
        $outputs[]=['rule'=>$rule['name'],'title'=>render_message($rule['title_template'],$vars),'message'=>render_message($rule['message_template'],$vars),'html'=>(bool)$rule['html'],'priority'=>(int)$rule['pushover_priority'],'sound'=>$rule['sound']];
        if($rule['stop_processing']) break;
    }
    return [$vars,$outputs];
}
function http_probe(string $url): array {
    $ch=curl_init($url); curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>6,CURLOPT_CONNECTTIMEOUT=>4,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_USERAGENT=>'CloudHub Signal Gateway/'.CSG_VERSION]);
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
    $api=http_probe('https://api.pushover.net/1/messages.json'); $feed=http_probe('https://status.pushover.net/rss'); $issue=!$feed['reachable']||feed_has_issue($feed['body']);
    if($api['reachable']&&!$issue) return ['level'=>'up','label'=>'Operational','note'=>'API and status feed are healthy.'];
    if($api['reachable']) return ['level'=>'warn','label'=>'Degraded','note'=>'The message API is reachable, but the Pushover status feed reports an issue.'];
    if($issue) return ['level'=>'down','label'=>'Down','note'=>'The message API check failed and the Pushover status feed reports an issue.'];
    return ['level'=>'warn','label'=>'Uncertain','note'=>'The API check failed while the status feed reports no incident.'];
}
function smtp_probe(): array {
    $host=setting('smtp_host'); $port=(int)setting('smtp_port','587'); $url=setting('smtp_status_url');
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
    $host=setting('smtp_host');$port=(int)setting('smtp_port','587');$security=setting('smtp_security','starttls');$user=setting('smtp_user');$password=dec(setting('smtp_password'));$from=setting('smtp_from',$user);$name=setting('smtp_from_name','CloudHub Signal Gateway');
    if($host===''||!filter_var($to,FILTER_VALIDATE_EMAIL)||!filter_var($from,FILTER_VALIDATE_EMAIL))return'not_configured';$subject=str_replace(["\r","\n"],' ',$subject);$name=str_replace(["\r","\n"],' ',$name);$prefix=$security==='ssl'?'ssl://':'tcp://';$errno=0;$err='';$s=@stream_socket_client($prefix.$host.':'.$port,$errno,$err,10);if(!$s)return'failed:connect';stream_set_timeout($s,10);
    if(!smtp_command($s,'',[220])||!smtp_command($s,'EHLO alarm.example.com',[250])){fclose($s);return'failed:greeting';}
    if($security==='starttls'){if(!smtp_command($s,'STARTTLS',[220])||!stream_socket_enable_crypto($s,true,STREAM_CRYPTO_METHOD_TLS_CLIENT)||!smtp_command($s,'EHLO alarm.example.com',[250])){fclose($s);return'failed:tls';}}
    if($user!==''&&!smtp_command($s,'AUTH LOGIN',[334])){fclose($s);return'failed:auth';}
    if($user!==''&&(!smtp_command($s,base64_encode($user),[334])||!smtp_command($s,base64_encode($password),[235]))){fclose($s);return'failed:auth';}
    if(!smtp_command($s,'MAIL FROM:<'.$from.'>',[250])||!smtp_command($s,'RCPT TO:<'.$to.'>',[250,251])||!smtp_command($s,'DATA',[354])){fclose($s);return'failed:recipient';}
    $headers='From: '.$name.' <'.$from.">\r\n".'To: <'.$to.">\r\n".'Subject: '.$subject."\r\n".'MIME-Version: 1.0'."\r\n".'Content-Type: text/html; charset=UTF-8'."\r\n";
    fwrite($s,$headers."\r\n".str_replace("\n.","\n..",$html)."\r\n.\r\n");$ok=smtp_command($s,'',[250]);smtp_command($s,'QUIT',[221]);fclose($s);return$ok?'sent':'failed:data';
}
function send_pushover(array $output): string {
    $token=dec(setting('pushover_token'));$user=dec(setting('pushover_user'));if($token===''||$user==='')return'not_configured';
    $ch=curl_init('https://api.pushover.net/1/messages.json');curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>10,CURLOPT_POSTFIELDS=>['token'=>$token,'user'=>$user,'title'=>substr($output['title'],0,250),'message'=>substr($output['message'],0,1024),'html'=>$output['html']?1:0,'priority'=>$output['priority'],'sound'=>$output['sound']]]);curl_exec($ch);$code=(int)curl_getinfo($ch,CURLINFO_RESPONSE_CODE);curl_close($ch);return$code>=200&&$code<300?'sent':'failed:'.$code;
}
function deliver(array $output): string {
    $push=send_pushover($output);if($push==='sent')return'pushover:sent';
    if(setting('email_fallback')==='1'){$email=send_email(setting('profile_email'),$output['title'],$output['message']);return'pushover:'.$push.',email:'.$email;}
    return'pushover:'.$push;
}
function log_event(array $entry): void {
    $path=cfg()['event_log']??'/srv/www/.signal-gateway/signal-events.ndjson';
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
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'.h($title).'</title><link rel="stylesheet" href="/assets/style.css"></head><body><header><img class="brand" src="/assets/logo.png" alt="CloudHub Signal Gateway"></header><main>';
}
function page_end(): void {
    echo '</main><footer><a href="'.CSG_GITHUB.'" target="_blank" rel="noopener">CloudHub Signal Gateway v'.CSG_VERSION.'</a><span>© '.date('Y').' <a href="'.CSG_AUTHOR.'" target="_blank" rel="noopener">Terry Rogers</a></span></footer></body></html>';
}
function require_admin(): void {session_start_secure();if(empty($_SESSION['admin'])){header('Location:/admin');exit;}}

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
    http_response_code(202);echo json_encode(['accepted'=>true,'matched_rules'=>array_column($outputs,'rule'),'status'=>$status]);exit;
}

session_start_secure();$setup=setting('admin_hash')==='';
if($path==='/admin/setup'){
    $ok=$setup&&hash_equals(cfg()['setup_token'],(string)($_GET['token']??$_POST['token']??''));$error='';
    if($_SERVER['REQUEST_METHOD']==='POST'&&$ok){$password=(string)($_POST['password']??'');if(strlen($password)<12)$error='Use at least 12 characters.';else{setv('admin_hash',password_hash($password,PASSWORD_DEFAULT));header('Location:/admin');exit;}}
    page_start('Admin Setup');echo'<section class="card narrow"><h1>Admin Setup</h1>';if(!$setup)echo'<p>Setup is complete. <a href="/admin">Sign In</a>.</p>';elseif(!$ok)echo'<p class="error">A valid one-time setup link is required.</p>';else echo($error?'<p class="error">'.h($error).'</p>':'').'<p>Choose an administrator password. This setup link is disabled afterwards.</p><form method="post"><input type="hidden" name="token" value="'.h(cfg()['setup_token']).'"><label>New Password<input type="password" name="password" minlength="12" required autofocus></label><button>Complete Setup</button></form>';echo'</section>';page_end();exit;
}
if($path==='/admin/forgot'){
    session_start_secure();$notice='';if($_SERVER['REQUEST_METHOD']==='POST'){$last=(int)($_SESSION['reset_requested_at']??0);if(time()-$last>=60){$_SESSION['reset_requested_at']=time();$channel=$_POST['channel']??'email';$token=bin2hex(random_bytes(32));$q=db()->prepare('INSERT INTO reset_tokens(token_hash,expires_at)VALUES(?,?)');$q->execute([hash('sha256',$token),time()+1800]);$scheme=((!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')||strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO']??''))==='https')?'https':'http';$link=$scheme.'://alarm.example.com/admin/reset?token='.$token;$message='<b>Password reset requested.</b><br><a href="'.$link.'">Reset Password</a><br>This link expires in 30 minutes.';$result=$channel==='pushover'?send_pushover(['title'=>'Signal Gateway Password Reset','message'=>$message,'html'=>true,'priority'=>0,'sound'=>'pushover']):send_email(setting('profile_email'),'Signal Gateway Password Reset',$message);if($result!=='sent')db()->prepare('DELETE FROM reset_tokens WHERE token_hash=?')->execute([hash('sha256',$token)]);}$notice='If that recovery channel is configured and available, a reset link has been sent.';}
    page_start('Forgot Password');echo'<section class="card narrow"><h1>Forgot Password</h1>'.($notice?'<p class="status">'.h($notice).'</p>':'').'<p>Send a single-use link that expires after 30 minutes.</p><form method="post"><label>Recovery Channel<select name="channel"><option value="email">Email</option><option value="pushover">Pushover</option></select></label><button>Send Reset Link</button></form><p><a href="/admin">Back To Sign In</a></p></section>';page_end();exit;
}
if($path==='/admin/reset'){
    $token=(string)($_GET['token']??$_POST['token']??'');$q=db()->prepare('SELECT id FROM reset_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>=? ORDER BY id DESC LIMIT 1');$q->execute([hash('sha256',$token),time()]);$id=$q->fetchColumn();$error='';
    if($_SERVER['REQUEST_METHOD']==='POST'&&$id){$password=(string)($_POST['password']??'');if(strlen($password)<12)$error='Use at least 12 characters.';else{setv('admin_hash',password_hash($password,PASSWORD_DEFAULT));db()->prepare('UPDATE reset_tokens SET used_at=? WHERE id=?')->execute([time(),$id]);session_destroy();header('Location:/admin');exit;}}
    page_start('Reset Password');echo'<section class="card narrow"><h1>Reset Password</h1>';if(!$id)echo'<p class="error">This reset link is invalid or expired.</p>';else echo($error?'<p class="error">'.h($error).'</p>':'').'<form method="post"><input type="hidden" name="token" value="'.h($token).'"><label>New Password<input type="password" name="password" minlength="12" required></label><button>Change Password</button></form>';echo'</section>';page_end();exit;
}
if($setup){header('Location:/admin/setup');exit;}
if(empty($_SESSION['admin'])){
    $error='';if($_SERVER['REQUEST_METHOD']==='POST'&&password_verify((string)($_POST['password']??''),setting('admin_hash'))){session_regenerate_id(true);$_SESSION['admin']=true;$_SESSION['csrf']=bin2hex(random_bytes(24));header('Location:/admin');exit;}elseif($_SERVER['REQUEST_METHOD']==='POST')$error='Incorrect password.';
    page_start('Admin Sign In');echo'<section class="card narrow"><h1>Admin Sign In</h1>'.($error?'<p class="error">'.h($error).'</p>':'').'<form method="post"><label>Password<input type="password" name="password" required autofocus></label><button>Sign In</button></form><p><a href="/admin/forgot">Forgot Password?</a></p></section>';page_end();exit;
}
if($path==='/admin/inspect'){require_csrf();header('Content-Type:application/json');$payload=json_decode((string)($_POST['payload']??''),true);if(!is_array($payload)){http_response_code(400);echo json_encode(['error'=>'Invalid JSON']);exit;}[$vars,$outputs]=evaluate($payload);echo json_encode(['variables'=>$vars,'outputs'=>$outputs],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);exit;}
$message='';
if($_SERVER['REQUEST_METHOD']==='POST'){
    require_csrf();$action=$_POST['action']??'';
    if($action==='logout'){session_destroy();header('Location:/admin');exit;}
    if($action==='settings'){foreach(['app_name','smtp_host','smtp_port','smtp_security','smtp_user','smtp_from','smtp_from_name','smtp_status_url','profile_email']as$key)setv($key,trim((string)($_POST[$key]??setting($key))));setv('email_fallback',isset($_POST['email_fallback'])?'1':'0');foreach(['pushover_token','pushover_user','smtp_password']as$key)if((string)($_POST[$key]??'')!=='')setv($key,enc((string)$_POST[$key]));$message='Settings saved.';}
    if($action==='test_pushover')$message='Pushover test: '.send_pushover(['title'=>'CloudHub Signal Gateway Test','message'=>'<b>Test successful.</b> Pushover settings are working.','html'=>true,'priority'=>0,'sound'=>'pushover']);
    if($action==='test_email')$message='Email test: '.send_email(setting('profile_email'),'CloudHub Signal Gateway Test','<b>Test successful.</b> Email settings are working.');
    if($action==='clear_events'){db()->exec('DELETE FROM events');$message='Recent events cleared.';}
    if($action==='clear_log'){$log=cfg()['event_log']??'/srv/www/.signal-gateway/signal-events.ndjson';file_put_contents($log,'',LOCK_EX);$message='Captured payload log cleared.';}
    if($action==='delete_rule'){db()->prepare('DELETE FROM rules WHERE id=?')->execute([(int)$_POST['id']]);$message='Rule deleted.';}
    if($action==='rule'){$conditions=json_decode((string)($_POST['conditions']??'[]'),true);if(!is_array($conditions))$message='Conditions must be valid JSON.';else{$values=[(string)$_POST['name'],isset($_POST['enabled'])?1:0,(int)$_POST['priority'],($_POST['match_mode']??'all')==='any'?'any':'all',json_encode($conditions),(string)$_POST['title_template'],(string)$_POST['message_template'],isset($_POST['html'])?1:0,(int)$_POST['pushover_priority'],(string)$_POST['sound'],isset($_POST['stop_processing'])?1:0];if((int)($_POST['id']??0)>0){$q=db()->prepare('UPDATE rules SET name=?,enabled=?,priority=?,match_mode=?,conditions=?,title_template=?,message_template=?,html=?,pushover_priority=?,sound=?,stop_processing=? WHERE id=?');$values[]=(int)$_POST['id'];}else$q=db()->prepare('INSERT INTO rules(name,enabled,priority,match_mode,conditions,title_template,message_template,html,pushover_priority,sound,stop_processing)VALUES(?,?,?,?,?,?,?,?,?,?,?)');$q->execute($values);$message='Rule saved.';}}
    if($action==='profile'){setv('profile_email',trim((string)($_POST['profile_email']??'')));if((string)($_POST['new_password']??'')!==''){if(strlen((string)$_POST['new_password'])<12)$message='Password must be at least 12 characters.';else{setv('admin_hash',password_hash((string)$_POST['new_password'],PASSWORD_DEFAULT));$message='Profile and password updated.';}}else$message='Profile updated.';if(isset($_FILES['profile_picture'])&&$_FILES['profile_picture']['error']===UPLOAD_ERR_OK&&$_FILES['profile_picture']['size']<=2097152){$mime=(new finfo(FILEINFO_MIME_TYPE))->file($_FILES['profile_picture']['tmp_name']);$ext=['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'][$mime]??'';if($ext!==''){$relative='profile.'.$ext;$target=dirname(cfg()['database']).'/'.$relative;if(move_uploaded_file($_FILES['profile_picture']['tmp_name'],$target)){chmod($target,0640);setv('profile_picture',$relative);}}}}
}
$rules=db()->query('SELECT * FROM rules ORDER BY priority,id')->fetchAll(PDO::FETCH_ASSOC);$events=db()->query('SELECT * FROM events ORDER BY id DESC LIMIT 50')->fetchAll(PDO::FETCH_ASSOC);$pushStatus=pushover_status();$mailStatus=smtp_probe();$logEntries=[];$log=cfg()['event_log']??'/srv/www/.signal-gateway/signal-events.ndjson';if(is_file($log)){$lines=file($log,FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES)?:[];foreach(array_slice(array_reverse($lines),0,50)as$line){$item=json_decode($line,true);if(is_array($item))$logEntries[]=$item;}}
page_start('Signal Gateway Admin');
?>
<div class="top"><div><h1>Rules &amp; Outputs</h1><p>Match any incoming payload item and use it in a message template.</p></div><div class="actions"><img class="avatar" src="<?=h(profile_url())?>" alt="Profile"><a class="button secondary" href="/admin/settings">Settings</a><form method="post"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="logout"><button class="secondary">Sign Out</button></form></div></div>
<?php if($message):?><p class="notice"><?=h($message)?></p><?php endif;?>
<?php if($path==='/admin/settings'):?>
<section class="card"><h2>Profile Settings</h2><form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="profile"><label>Email Address<input type="email" name="profile_email" value="<?=h(setting('profile_email'))?>" required></label><label>Profile Picture <span>JPEG, PNG, or WebP; defaults to Gravatar.</span><input type="file" name="profile_picture" accept="image/jpeg,image/png,image/webp"></label><label>New Password <span>Leave blank to keep the current password.</span><input type="password" name="new_password" minlength="12"></label><button>Save Profile</button></form><p><a href="/admin">Back To Dashboard</a></p></section>
<?php else:?>
<section class="grid services">
<article class="card"><div class="tilehead"><h2>Pushover Settings</h2><span class="indicator <?=$pushStatus['level']?>"><?=$pushStatus['label']?></span></div><p class="service-note"><?=h($pushStatus['note'])?></p><form method="post"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="settings"><label>Application API Token<input type="password" name="pushover_token" placeholder="Leave blank to keep current value"></label><label>User Or Group Key<input type="password" name="pushover_user" placeholder="Leave blank to keep current value"></label><button>Save Settings</button></form><form method="post" class="testform"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="test_pushover"><button class="secondary">Test Pushover</button></form></article>
<article class="card"><div class="tilehead"><h2>Email Settings</h2><span class="indicator <?=$mailStatus['level']?>"><?=$mailStatus['label']?></span></div><p class="service-note"><?=h($mailStatus['note'])?></p><form method="post"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="settings"><label>SMTP Host<input name="smtp_host" value="<?=h(setting('smtp_host'))?>"></label><div class="fields"><label>Port<input type="number" name="smtp_port" value="<?=h(setting('smtp_port','587'))?>"></label><label>Security<select name="smtp_security"><option value="starttls">STARTTLS</option><option value="ssl" <?=setting('smtp_security')==='ssl'?'selected':''?>>TLS/SSL</option><option value="none" <?=setting('smtp_security')==='none'?'selected':''?>>None</option></select></label></div><label>Username<input name="smtp_user" value="<?=h(setting('smtp_user'))?>"></label><label>Password<input type="password" name="smtp_password" placeholder="Leave blank to keep current value"></label><label>From Address<input type="email" name="smtp_from" value="<?=h(setting('smtp_from'))?>"></label><label>From Name<input name="smtp_from_name" value="<?=h(setting('smtp_from_name','CloudHub Signal Gateway'))?>"></label><label>Provider Status Page URL<input type="url" name="smtp_status_url" value="<?=h(setting('smtp_status_url'))?>"></label><label>Recovery Email<input type="email" name="profile_email" value="<?=h(setting('profile_email'))?>"></label><label class="check"><input type="checkbox" name="email_fallback" <?=setting('email_fallback')==='1'?'checked':''?>> Use Email If Pushover Is Unavailable</label><button>Save Settings</button></form><form method="post" class="testform"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="test_email"><button class="secondary">Test Email</button></form></article>
</section>
<section class="card full"><h2>Payload Inspector</h2><p>Paste a payload to list every flattened variable and preview matched outputs without sending.</p><form method="post" action="/admin/inspect" target="inspect-result"><input type="hidden" name="csrf" value="<?=csrf()?>"><textarea name="payload" rows="10">{"events":[{"alert_key":"CLIENT_CONNECTED","scope":{"site_id":"example"}}]}</textarea><button>Inspect Payload</button></form></section>
<section class="card"><h2>Create Or Update Rule</h2><form method="post" class="ruleform"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="rule"><label>Rule ID <span>Leave blank to create</span><input name="id" type="number"></label><label>Rule Name<input name="name" required></label><label>Priority<input name="priority" type="number" value="100"></label><label>Match Mode<select name="match_mode"><option value="all">All Conditions</option><option value="any">Any Condition</option></select></label><label class="wide">Conditions JSON<textarea name="conditions" rows="4">[{"path":"events.*.alert_key","operator":"equals","value":"CLIENT_CONNECTED"}]</textarea></label><label class="wide">Title Template<input name="title_template" value="UniFi: {{ events.0.alert_key }}"></label><label class="wide">Message Template<textarea name="message_template" rows="4">Event &lt;b&gt;{{ events.0.alert_key }}&lt;/b&gt; occurred at site {{ events.0.scope.site_id }}.</textarea></label><label>Pushover Priority<input name="pushover_priority" type="number" min="-2" max="2" value="0"></label><label>Sound<input name="sound" value="pushover"></label><label class="check"><input type="checkbox" name="enabled" checked> Enabled</label><label class="check"><input type="checkbox" name="html" checked> Enable HTML</label><label class="check"><input type="checkbox" name="stop_processing"> Stop After Match</label><button>Save Rule</button></form></section>
<section class="card"><div class="tilehead"><h2>Recent Events</h2><form method="post" onsubmit="return confirm('Clear all recent events?')"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="clear_events"><button class="danger">Clear Events</button></form></div><div class="eventlist"><?php foreach($events as$event):$payload=json_decode($event['payload'],true);?><details><summary><strong><?=h($event['received_at'])?></strong> · <?=h($event['status'])?> · <?=h(implode(', ',json_decode($event['matched_rules'],true)?:['No Rule']))?></summary><pre><?=h(json_encode($payload,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE))?></pre></details><?php endforeach;?><?php if(!$events):?><p>No events captured.</p><?php endif;?></div></section>
<section class="card"><div class="tilehead"><div><h2>Captured Payload Log</h2><p>Integrated diagnostic log: <code>signal-events.ndjson</code></p></div><form method="post" onsubmit="return confirm('Clear the captured payload log?')"><input type="hidden" name="csrf" value="<?=csrf()?>"><input type="hidden" name="action" value="clear_log"><button class="danger">Clear Log</button></form></div><div class="eventlist"><?php foreach($logEntries as$entry):?><details><summary><strong><?=h((string)($entry['received_at']??'Unknown time'))?></strong> · <?=h((string)($entry['status']??'Unknown'))?></summary><pre><?=h(json_encode($entry,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE))?></pre></details><?php endforeach;?><?php if(!$logEntries):?><p>No diagnostic payloads captured.</p><?php endif;?></div></section>
<?php endif; page_end();
