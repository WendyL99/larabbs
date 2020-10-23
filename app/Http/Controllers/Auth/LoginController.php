<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Providers\RouteServiceProvider;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use App\Models\User;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = RouteServiceProvider::HOME;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    public function username()
    {
        return 'name';
    }

    /**
     * 结合ldap实现登录操作
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse|\Illuminate\Http\RedirectResponse|\Symfony\Component\HttpFoundation\Response|void
     * @throws \Illuminate\Validation\ValidationException
     */
    public function login(Request $request)
    {
        $host = env('GZLDAP_HOST');
        $port = env('GZLDAP_PORT');
        $base_dn = env('GZLDAP_BASE_DN');
        $dn = 'cn='.$request->name.','.$base_dn;

        $ds = ldap_connect($host,$port)
                or die("Could not connect to LDAP server.");

        ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);

        if ($ds) {
            $r = ldap_bind($ds, $dn, $request->password);

            if(!$r){
                echo ldap_error($dn);
                exit;
            }else{
                //若该用户是新用户，进行用户信息保存；若是旧用户，刷新本地密码然后进行登录
                $filter = '(cn='.$request->name.')';
                $res = ldap_search($ds, $dn, $filter);
                $res = ldap_get_entries($ds, $res);

                $user = User::where('name', $request->name)->first();
                if($user){
                    $user->password = bcrypt($request->password); //刷新本地密码
                    $user->save();
                }else{
                    $data = [
                        'name' => $request->name,
                        'email' => $res[0]['mail'][0],
                        'password' => bcrypt($request->password),
                        'job_title' => $res[0]['title'][0],
                        'departmentId' => $res[0]['departmentnumber'][0],
                        'description' => $res[0]['description'][0]
                    ];
                    User::create($data);
                }
            }

        } else {
            die("Unable to connect to LDAP server");
        }

        ldap_unbind($ds); //close ldap connection

        $this->validateLogin($request);

        // If the class is using the ThrottlesLogins trait, we can automatically throttle
        // the login attempts for this application. We'll key this by the username and
        // the IP address of the client making these requests into this application.
        if (method_exists($this, 'hasTooManyLoginAttempts') &&
            $this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            return $this->sendLockoutResponse($request);
        }

        if ($this->attemptLogin($request)) {
            return $this->sendLoginResponse($request);
        }

        // If the login attempt was unsuccessful we will increment the number of attempts
        // to login and redirect the user back to the login form. Of course, when this
        // user surpasses their maximum number of attempts they will get locked out.
        $this->incrementLoginAttempts($request);

        return $this->sendFailedLoginResponse($request);
    }
}
