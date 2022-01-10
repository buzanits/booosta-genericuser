<?php
namespace booosta\genericuser;
use \booosta\Framework as b;
b::init_module('genericuser');

class Genericuser extends \booosta\base\Module
{ 
  use moduletrait_genericuser;

  protected $valid;
  protected $user_type = 'user';
  public $authenticator;
  protected $id, $username, $password;
  protected $settings;
  

  public function __construct($username = null, $password = null, $param = [])
  {
    parent::__construct();

    $this->before_construct($username, $password, $param);

    #\booosta\debug(\booosta\Framework::$classmap);
    #\booosta\debug($param);

    $this->authenticator = $this->make_authenticator();

    // username = null means cookie authentication
    if($username === null):
      $username = $this->authenticate_cookie();
      $authenticated = $username !== false;
    else:
      if($param['login_param_1']) $authenticated = $this->authenticate($username, $password, $param['login_param_1']);
      else $authenticated = $this->authenticate($username, $password);
    endif;

    if(is_callable([$this, 'make_privileges'])) $this->privileges = $this->make_privileges();

    if($authenticated):
      $this->valid = true;

      $this->id = $this->authenticator->get_id($username);
      $this->username = $username;
      $this->password = $password;
      $this->settings = $this->authenticator->get_settings($username);

      $this->after_auth_success();
    else:
      $this->valid = false;
      $this->error($this->authenticator);
      $this->after_auth_failure();

      #$_SESSION['login_failure'] = true;
    endif;

    #\booosta\debug('this:'); \booosta\debug(get_class($this));

    // save user in session, but without the DB object (it will be invalid after the actual script has run)
    if($authenticated && $param['save_in_session'] !== false):
      #$this->debug_id = uniqid();
      $userobj = clone $this;
      $userobj->DB = null;
      $userobj->parentobj = null;
      $userobj->topobj = null;

      if(is_object($userobj->authenticator)):
        $userobj->authenticator->DB = null;
        $userobj->authenticator->parentobj = null;
        $userobj->authenticator->topobj = null;
      endif;

      if(is_object($userobj->privileges)):
        $userobj->privileges->DB = null;
        $userobj->privileges->parentobj = null;
        $userobj->privileges->topobj = null;
      endif;

      $_SESSION['AUTH_USER'] = serialize($userobj);
      #\booosta\debug($userobj);
    endif;

    // save login cookie
    if($authenticated && $param['store_logincookie']):
      $secret = $this->authenticator->get_logincookie($this->username) ?? md5(uniqid(true));   // if secret already exists, do not create a new one
      setcookie('loginCredentials', serialize(['username' => $this->username, 'secret' => $secret]), 2147483647, '/');
      $this->authenticator->store_logincookie($this->username, $secret);
    endif;

    $this->after_construct($username, $password, $param);

    if($this->config('LOG_MODE')) $this->log($username, $authenticated);
  }

  public function after_logout()
  {
    #\booosta\debug("after_logout $this->username");
    setcookie('loginCredentials', false, 2147483647, '/');
    $this->authenticator->delete_logincookie($this->username);
  }


  public function is_valid() { return $this->valid; }
  protected function before_construct($username, $password, $param) {}
  protected function after_construct($username, $password, $param) {}
  protected function after_auth_success() {}
  protected function after_auth_failure() {}

  protected function make_authenticator() { return $this->makeInstance('DB_Authenticator'); }
  protected function authenticate($username, $password, $param = []) { return $this->authenticator->authenticate($username, $password, $param); }
  protected function authenticate_cookie() { return $this->authenticator->authenticate_cookie(); }

  public function member_of($group)
  {
    if(!is_numeric($group)) $group = $this->DB->query_value("select id from usergroup where name='$group'");
    return $this->get_usergroup() == $group;
  }

  protected function log($username, $success)
  {
    $obj = $this->makeDataobject('log_login');
    if(!is_object($obj)) return;

    $obj->set('user', $username);
    $obj->set('time', date('Y-m-d H:i:s'));
    $obj->set('ip', $_SERVER['REMOTE_ADDR']);
    $obj->set('success', $success);
    $obj->set('usertype', $this->user_type);

    $obj->insert();
  }

  public function get_user_type() { return $this->user_type; }
  public function get_username() { return $this->username; }
  public function get_id() { return $this->id; }
  public function get_settings() { return $this->settings; }

  public function get_setting($key)
  {
    $settings = $this->get_settings();
    return $settings[$key];
  }
}
