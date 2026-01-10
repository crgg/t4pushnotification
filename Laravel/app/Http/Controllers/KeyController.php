<?php

namespace App\Http\Controllers;

use App\Models\Keys;
use Illuminate\Http\Request;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\Http;
use Laravel\Prompts\Key;

class KeyController extends Controller
{
    public function index()
    {
        $auth = new AuthController();
        $auth->getToken();

        $token = $_SESSION['token'];

        $response = Http::withHeaders([
            'Accept' => 'application/json',
            'Authorization' => 'Bearer '.$token,
        ])->get(config('app.python_url').'keys/list');

        $body = json_decode($response->body());
        $items = Keys::hydrate($body->data);

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

        return view('keys.index', [
            'items' => $paginatedInstance,
        ]);
    }

    public function upload_key(Request $request)
    {
        $request->validate([
            "key_id" => 'required|string|min:10',
            "team_id" => 'required|string|min:10',
            "bundle_id" => 'required|string',
            "company_id" => 'integer|nullable',
            "file" => 'required|file',
        ]);

        $auth = new AuthController();
        $auth->getToken();

        $token = $_SESSION['token'];


        $file = $request->file('file');

        $response = Http::withHeaders([
            'Accept' => 'application/json',
            'Authorization' => 'Bearer ' . $token,
        ])
            ->attach(
                'file',
                fopen($file->getRealPath(), 'r'),
                $file->getClientOriginalName()
            )
            ->post(config('app.python_url') . 'upload/key', [
                'key_id'     => (string) $request->input('key_id'),
                'team_id'    => (string) $request->input('team_id'),
                'bundle_id'  => (string) $request->input('bundle_id'),
                'company_id' => (string) $request->input('company_id'),
            ]);

        if ($response->successful()) {
            return redirect()->route('keys.index');
        } else {
            return back()->withErrors($response->json());
        }
    }

    public function set_active_key(Request $request)
    {
        $request->validate([
            "bundle_id" => 'required|string',
        ]);

        $auth = new AuthController();
        $auth->getToken();

        $token = $_SESSION['token'];

        $response = Http::withHeaders([
            'Accept' => 'application/json',
            'Authorization' => 'Bearer ' . $token,
        ])->post(config('app.python_url') . 'keys/activate', [
            'bundle_id'     => (string) $request->input('bundle_id'),
        ]);

        if ($response->successful()) {
            return redirect()->route('keys.index');
        } else {
            return back()->withErrors($response->json());
        }
    }
}
