<?php

namespace App\Http\Controllers;

use App\Models\Company;
use Illuminate\Http\Request;

class CompanyController extends Controller
{
    public function index()
    {
        $items = Company::query()
            ->orderByDesc('id')
            ->paginate(15);

        return view('company.index', [
            'items' => $items
        ]);
    }
}
