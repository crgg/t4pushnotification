<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Http;

class AuthController extends Controller
{
    public function getToken() : void
    {
        $response = Http::post(config('app.python_url'). 'auth/login', [
            "passphrase" => config('app.passphrase'),
        ]);
        $body = json_decode($response->body());
        $token = $body->token;
        $_SESSION['token'] = $token;
    }
}
