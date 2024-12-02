<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
class AuthController extends Controller
{
    public function register(Request $request):JsonResponse
    {
        $request->validate([
            'first_name' => ['required'],
            'last_name' => ['required'],
            'phone_number' => ['required' , 'unique:users' , 'min:10' , 'max:10'],
            'password' => ['required', 'min:8'],
        ]);
        $user = User::query()->create([
            'first_name' => $request['first_name'],
            'last_name' => $request['last_name'],
            'phone_number' => $request['phone_number'],
            'password' => $request['password'],
        ]);
        $token = $user->createToken('auth_token')->plainTextToken;
        $data =[];
        $data ['user'] = $user;
        $data['token'] = $token;
        return response()->json([
            'status' => 1,
            'data' => $data,
            'message' => 'user registered successfully'
        ]);
    }
    public function login(Request $request){
        $request->validate([
            'phone_number' => ['required' , 'min:10' , 'max:10' ,'exists:users'],
            'password' => ['required'],
        ]);
        if(!Auth::attempt(['phone_number' => $request['phone_number'] , 'password' => $request['password']])){
            $message = 'Incorrect phone number or password';
            return response()->json([
                'status' => 0,
                'data' => [],
                'message' => $message
            ] , 500);
        }
        $user =User::query()->where('phone_number' , $request['phone_number'])->first();
        $token = $user->createToken('auth_token')->plainTextToken;
        $data =[];
        $data ['user'] = $user;
        $data['token'] = $token;
        return response()->json([
            'status' => 1,
            'data' => $data,
            'message' => 'user logged in successfully'
        ]);
    }
    public function logout(){
        Auth::user()->currentAccessToken()->delete();
        return response()->json([
            'status' => 1,
            'data' => [],
            'message' => 'user logged out successfully'
        ]);
    }
}

