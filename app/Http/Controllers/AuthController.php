<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Str;

class AuthController extends Controller
{


    public function createAccount(Request $request){
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ]);

        $user = User::create([
            'user_id'=>Str::uuid(),
            'name'=>$request->name, 
            'email'=>$request->email,
            'password'=>Hash::make($request->password),
            'verification_code'=>random_int(111111, 999999), // Generate random 6 digit number
        ]);

        return response()->json(['message' => 'Your account has been created successfully'], 201);
    }

    public function authenticate(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required',
        ]);
    
        $user = User::where('email', $request->email)->first();
    
        if (!$user || !Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => 'The provided credentials are incorrect'
            ]);
        }
    
        if ($user->email_verified_at === null) {
            $verificationUrl = env('FRONTEND_APP_URL') . '/authentication/verification/email-verification/' . $user->user_id;  // Ensure this is correct
        
            return response()->json([
                'message' => 'Your account has not yet been verified. You must verify your email before you can log in.',
                'verification_url' => $verificationUrl,
                'email'=>$user->email
            ], 403); // Ensure the status code is 403
        }
        
        $token = $user->createToken('auth_token')->plainTextToken;
    
        return response()->json(['access_token' => $token, 'token_type' => 'Bearer']);
    }

    public function verifyEmail(Request $request, $uuid){
        \Log::info('Email verification started for UUID: ' . $uuid);
        $user = User::findOrFail($uuid); 
        \Log::info(['User: ', $user]);
    
        try {
            $code = intval($request->code);
            \Log::info('Code Entered: ' . $code);
    
            if ($code !== $user->verification_code) {
                \Log::error('Wrong code entered. Code Entered: ' . $code . '. Right Code: ' . $user->verification_code);
                return response()->json(['error' => 'Code entered is invalid. Check your email and try again']);
            }
    
            // If user entered the right code, set verified at date in the DB 
            $user->email_verified_at = now();
            $user->save();
    
            \Log::info('Email verified successfully for UUID: ' . $uuid);
            return response()->json(['success' => 'Email verified successfully']);
        } catch (\Exception $e) {
            \Log::error('Uncaught Exception: ' . $e->getMessage());
            return response()->json(['error' => 'An error occurred while verifying email']);
        }
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
