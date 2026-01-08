<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Keys extends Model
{
    protected $table = 'apn_keys';


    public function company()
    {
        return $this->belongsTo(Company::class);
    }
}
