<?php

namespace App\Http\Controllers;

use App\Models\NotificationLog;
use Illuminate\Http\Request;

class NotificationLogController extends Controller
{
    public function index()
    {
        $items = NotificationLog::query()
            ->orderByDesc('id')
            ->paginate(15);

        return view('notification_logs.index', compact('items'));
    }
}
