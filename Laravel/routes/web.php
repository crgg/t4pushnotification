<?php

use App\Http\Controllers\CompanyController;
use App\Http\Controllers\KeyController;
use App\Http\Controllers\NotificationLogController;
use Illuminate\Support\Facades\Route;

Route::redirect('/', 'login');

Route::view('dashboard', 'dashboard')
    ->middleware(['auth', 'verified'])
    ->name('dashboard');

Route::view('profile', 'profile')
    ->middleware(['auth'])
    ->name('profile');

Route::get('logs',[NotificationLogController::class,'index'])
    ->middleware(['auth'])
    ->name('notification_logs.index');

Route::get('keys',[KeyController::class,'index'])
    ->middleware(['auth'])
    ->name('keys.index');

Route::get('companies',[CompanyController::class,'index'])
    ->middleware(['auth'])
    ->name('companies.index');

Route::post('upload_key',[KeyController::class,'upload_key']);

Route::post('activate_key',[KeyController::class,'set_active_key']);

Route::post('send_notification',[NotificationLogController::class,'send_notification']);

require __DIR__.'/auth.php';
