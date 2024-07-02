<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::post('/createAccount', [AuthController::class, 'createAccount']);
Route::post('/authenticate', [AuthController::class, 'authenticate']);
 Route::middleware('auth:sanctum')->post('/logout', [AuthController::class, 'logout']);
