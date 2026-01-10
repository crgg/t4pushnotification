<?php

namespace App\Http\Controllers;

use App\Models\NotificationLog;
use Illuminate\Http\Request;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\Http;

class NotificationLogController extends Controller
{
    public function index()
    {
        $auth = new AuthController();
        $auth->getToken();

        $token = $_SESSION['token'];

        $response = Http::withHeaders([
            'Accept' => 'application/json',
            'Authorization' => 'Bearer '.$token,
        ])->get(config('app.python_url').'logs');

        $body = json_decode($response->body());
        $items = NotificationLog::hydrate($body->data);

        $perPage = 15;
        $currentPage = LengthAwarePaginator::resolveCurrentPage();
        $offset = ($currentPage * $perPage) - $perPage;

        $currentPageItems = $items->slice($offset, $perPage)->all();

        $paginatedInstance = new LengthAwarePaginator(
            $currentPageItems,
            $items->count(),
            $perPage,
            $currentPage,
            ['path' => LengthAwarePaginator::resolveCurrentPath()]
        );

        return view('notification_logs.index',[
            'items' => $paginatedInstance,
        ]);
    }

    public function send_notification(Request $request)
    {
        $request->validate([
            "device_token" => 'required|string',
            "message" => 'required|string',
            "title" => 'required|string',
        ]);

        $auth = new AuthController();
        $auth->getToken();

        $token = $_SESSION['token'];

        $response = Http::withHeaders([
            'Accept' => 'application/json',
            'Authorization' => 'Bearer ' . $token,
        ])
        ->asJson()
        ->post(config('app.python_url') . 'send', [
            "device_token" => $request->get('device_token'),
            "message" => $request->get('message'),
            "title" => $request->get('title'),
            "pushtype" => "alert",
            "priority" => "high"
        ]);

        if ($response->successful()) {
            return redirect()->route('keys.index');
        } else {
            return back()->withErrors($response->json());
        }
    }
}
