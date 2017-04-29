<?php

use Illuminate\Database\Schema\Blueprint;

class RemoveModelFromPermissions extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('permissions', function ($table) {
            $table
                ->dropColumn('model');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('permissions', function ($table) {
            $table
                ->string('model')
                ->nullable();
        });
    }
}
