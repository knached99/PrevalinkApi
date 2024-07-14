<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{


    public function createAccount(Request $request){
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ]);

        $user = User::create([
            'name'=>$request->name, 
            'email'=>$request->email,
            'password'=>Hash::make($request->password),
        ]);

        return response()->json(['message' => 'Your account has been created successfully'], 201);
    }

    public function authenticate(Request $request){

        $request->validate([
            'email'=>'required|string|email',
            'password'=>'required',
        ]);

        $user = User::where('email', $request->email)->first();

        if(!$user || ! Hash::check($request->password, $user->password)){
            throw ValidationException::withMessages([
                'email'=>'The provided credentials are incorrect'
            ]);
        }

        if($user->email_verified_at === null){
            return response()->json(['message'=>'Your account has not yet ben verified. You must verify your email before you can login']);
        }

        $token = $user->createToken('auth_token')->plainTextToken; 
        /* Using platintext token with the context of
         Laravel Sanctum is secure  
         */
        
        return response()->json(['access_token'=> $token, 'token_type'=>'Bearer']);
    }


    public function logout(Request $request)
    {   try{
        $user = Auth::user();
        $user->tokens()->delete(); // Revoke all tokens from all authenticated devices
        return response()->json(['message' => 'You have been logged out successfully']);
    }
    catch(\Exception $e){
        \Log::error('An error occurred while logging out: '. $e->getMessage());
        return response()->json(['Message'=>'Unauthorized Action', 401]);
    }
    }
}
