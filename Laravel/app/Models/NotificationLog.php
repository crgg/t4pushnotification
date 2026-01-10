<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class NotificationLog extends Model
{
    protected $table = 'notification_logs';
    protected $primaryKey = 'id';

    protected $fillable = ['device_token','title','message','badge','sound','category','thread_id','custom_data','priority','success','error_code','error_message','apns_id','status_code','ip_address','created_at'];
}
