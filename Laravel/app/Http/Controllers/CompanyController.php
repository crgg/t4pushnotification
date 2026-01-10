<?php

namespace App\Http\Controllers;

use App\Models\Company;
use Illuminate\Http\Request;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Http;

class CompanyController extends Controller
{
    public function index(Request $request)
    {
        $auth = new AuthController();
        $auth->getToken();

        $token = $_SESSION['token'];

        $response = Http::withHeaders([
            'Accept' => 'application/json',
            'Authorization' => 'Bearer '.$token,
        ])->get(config('app.python_url').'companies/list');

        $body = json_decode($response->body());
        $items = Company::hydrate($body->data);

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

        return view('company.index', [
            'items' => $paginatedInstance
        ]);
    }
}
