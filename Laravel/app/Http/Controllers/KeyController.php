<?php

namespace App\Http\Controllers;

use App\Models\Keys;
use Illuminate\Http\Request;
use Laravel\Prompts\Key;

class KeyController extends Controller
{
    public function index()
    {
        $items = Keys::query()
            ->select(['key_id','p8_filename','is_active','bundle_id','id','company_id'])
            ->orderByDesc('id')
            ->paginate(15);

        return view('keys.index', compact('items'));
    }
}
