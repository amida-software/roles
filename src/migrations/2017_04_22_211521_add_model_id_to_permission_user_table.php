<?php

use Illuminate\Database\Schema\Blueprint;

class AddModelIdToPermissionUserTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('permission_user', function ($table) {
            $table
                ->integer('model_id')
                ->unsigned()
                ->nullable()
                ->after('user_id');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('permission_user', function ($table) {
            $table
                ->dropColumn('model_id');
        });
    }
}
