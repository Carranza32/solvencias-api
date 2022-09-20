<?php

namespace App\Http\Controllers;

use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function register(RegisterRequest $request)
    {
        try {
            $credentials = $request->all();

            $user = User::create([
                'name' => $credentials['name'],
                'password' => bcrypt($credentials['password']),
                'email' => $credentials['email']
            ]);

            return response()->json([
                'status' => true,
                'token' => $user->createToken('tokens')->plainTextToken,
                'message' => __('auth.success'),
            ], 200);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => __('api.error'),
            ], 400);
        }
    }

    public function login(LoginRequest $request)
    {
        try {
            $credentials = $request->all();

            if (! Auth::attempt( $credentials )) {
                return response()->json([
                    'status' => false,
                    'message' => __('auth.failed'),
                ], 401);
            }

            return response()->json([
                'status' => true,
                'token' => auth()->user()->createToken('API Token')->plainTextToken,
                'message' => __('auth.success'),
            ]);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => __('api.error'),
            ], 400);
        }
    }

    public function logout()
    {
        if (Auth::user()) {
            auth()->user()->tokens()->delete();

            return response()->json([
                'status' => true,
                'message' => 'Tokens Revoked'
            ]);
        }else{
            return response()->json([
                'status' => false,
                'message' => 'Not found'
            ], 404);
        }
    }
}
