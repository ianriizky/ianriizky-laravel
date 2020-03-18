<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Providers\RouteServiceProvider;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;

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

    /**
     * Show the application's login form.
     *
     * @return \Illuminate\Http\Response
     */
    public function showLoginForm()
    {
        return $this->socialiteDriver()->redirect();
    }

    /**
     * Obtain the user information from provider.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function handleProviderCallback(Request $request)
    {
        $socialiteUser = $this->socialiteDriver()->user();

        $guardProviderModel = $this->guard()->getProvider()->createModel();

        $user = $guardProviderModel::updateOrCreate([
            'email' => $socialiteUser->getEmail(),
        ], [
            'name' => $socialiteUser->getName(),
            'token' => $socialiteUser->token,
        ]);

        $this->guard()->login($user);

        return $this->sendLoginResponse($request);
    }

    /**
     * Get an OAuth provider implementation.
     *
     * @return \Laravel\Socialite\Contracts\Provider
     */
    protected function socialiteDriver()
    {
        return Socialite::driver('okta');
    }

    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\StatefulGuard
     */
    protected function guard()
    {
        return Auth::guard('web');
    }
}
