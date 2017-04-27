<?php

namespace Bican\Roles\Traits;

use Illuminate\Support\Str;
use Illuminate\Database\Eloquent\Model;
use Bican\Roles\Models\Permission;
use InvalidArgumentException;

trait HasRoleAndPermission
{
    /**
     * Property for caching roles.
     *
     * @var \Illuminate\Database\Eloquent\Collection|null
     */
    protected $roles;

    /**
     * Property for caching permissions.
     *
     * @var \Illuminate\Database\Eloquent\Collection|null
     */
    protected $permissions;

    /**
     * User belongs to many roles.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function roles()
    {
        return $this->belongsToMany(config('roles.models.role'))->withTimestamps();
    }

    /**
     * Get all roles as collection.
     *
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function getRoles()
    {
        return (!$this->roles) ? $this->roles = $this->roles()->get() : $this->roles;
    }

    /**
     * Check if the user has a role or roles.
     *
     * @param int|string|array $role
     * @param bool $all
     * @return bool
     */
    public function isRole($role, $all = false)
    {
        if ($this->isPretendEnabled()) {
            return $this->pretend('is');
        }

        return $this->{$this->getMethodName('is', $all)}($role);
    }

    /**
     * Check if the user has at least one role.
     *
     * @param int|string|array $role
     * @return bool
     */
    public function isOne($role)
    {
        foreach ($this->getArrayFrom($role) as $role) {
            if ($this->hasRole($role)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the user has all roles.
     *
     * @param int|string|array $role
     * @return bool
     */
    public function isAll($role)
    {
        foreach ($this->getArrayFrom($role) as $role) {
            if (!$this->hasRole($role)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if the user has role.
     *
     * @param int|string $role
     * @return bool
     */
    public function hasRole($role)
    {
        return $this->getRoles()->contains(function ($value, $key) use ($role) {
            return $role == $value->id || Str::is($role, $value->slug);
        });
    }

    /**
     * Attach role to a user.
     *
     * @param int|\Bican\Roles\Models\Role $role
     * @return null|bool
     */
    public function attachRole($role)
    {
        return (!$this->getRoles()->contains($role)) ? $this->roles()->attach($role) : true;
    }

    /**
     * Detach role from a user.
     *
     * @param int|\Bican\Roles\Models\Role $role
     * @return int
     */
    public function detachRole($role)
    {
        $this->roles = null;

        return $this->roles()->detach($role);
    }

    /**
     * Detach all roles from a user.
     *
     * @return int
     */
    public function detachAllRoles()
    {
        $this->roles = null;

        return $this->roles()->detach();
    }

    /**
     * Get role level of a user.
     *
     * @return int
     */
    public function level()
    {
        return ($role = $this->getRoles()->sortByDesc('level')->first()) ? $role->level : 0;
    }

    /**
     * Get all permissions from roles.
     *
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function rolePermissions()
    {
        $permissionModel = app(config('roles.models.permission'));

        if (!$permissionModel instanceof Model) {
            throw new InvalidArgumentException('[roles.models.permission] must be an instance of \Illuminate\Database\Eloquent\Model');
        }

        return $permissionModel::select(['permissions.*', 'permission_role.created_at as pivot_created_at', 'permission_role.updated_at as pivot_updated_at'])
                ->join('permission_role', 'permission_role.permission_id', '=', 'permissions.id')->join('roles', 'roles.id', '=', 'permission_role.role_id')
                ->whereIn('roles.id', $this->getRoles()->pluck('id')->all()) ->orWhere('roles.level', '<', $this->level())
                ->groupBy(['permissions.id','permissions.name', 'permissions.slug', 'permissions.description', 'permissions.model', 'permissions.created_at', 'permissions.updated_at', 'pivot_created_at', 'pivot_updated_at']);
    }

    /**
     * User belongs to many permissions.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function userPermissions()
    {
        return $this
            ->belongsToMany(config('roles.models.permission'))
            ->withPivot('model_id')
            ->withTimestamps();
    }

    /**
     * Get all permissions as collection.
     *
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function getPermissions()
    {
        if ($this->permissions) {
            return $this->permissions;
        }

        return $this->permissions = $this
                ->rolePermissions()
                ->get()
                ->reduce(function($carry, $permission) {
                    return $carry->push($permission);
                }, $this->userPermissions);
    }

    /**
     * Check if the user has a permission or permissions.
     *
     * @param int|string|array $permission
     * @param bool $all
     * @return bool
     */
    public function may($permission, $all = true)
    {
        if ($this->isPretendEnabled()) {
            return $this->pretend('may');
        }

        return $this->{$this->getMethodName('hasPermission', $all)}($permission);
    }

    /**
     * Check if the user has at least one permission.
     *
     * @param int|string|array $permission
     * @return bool
     */
    private function hasPermissionOne($permission)
    {
        foreach ($this->getArrayFrom($permission) as $permission) {
            if ($this->hasPermission($permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the user has all permissions.
     *
     * @param int|string|array $permission
     * @return bool
     */
    private function hasPermissionAll($permission)
    {
        foreach ($this->getArrayFrom($permission) as $permission) {
            if (!$this->hasPermission($permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if the user has a permission.
     *
     * @param int|string $permission
     * @return bool
     */
    public function hasPermission($permission)
    {
        return $this->getPermissions()->contains(function ($value, $key) use ($permission) {
            if ($value
                    ->pivot 
                && $value
                    ->pivot
                    ->model_id) {
                return false;
            }

            return $permission == $value->id || Str::is($permission, $value->slug);
        });
    }

    /**
     * Check if the user is allowed to manipulate with entity.
     *
     * @param string $providedPermission
     * @param int|\Illuminate\Database\Eloquent\Model $entity
     */
    public function allowed($providedPermission, $entity)
    {
        if ($this->isPretendEnabled()) {
            return $this->pretend('allowed');
        }

        return $this->isAllowed($providedPermission, $entity);
    }

    /**
     * Check if the user is allowed to manipulate with provided entity.
     *
     * @param string $providedPermission
     * @param int|\Illuminate\Database\Eloquent\Model $entity
     * @return bool
     */
    protected function isAllowed($providedPermission, $entity)
    {
        if ($entity instanceof Model) {
            $model_id = $entity->id;
        } else {
            $model_id = $entity;
        }

        foreach ($this->getPermissions() as $permission) {
            if ((!$permission->pivot
                    || !$permission
                            ->pivot
                            ->model_id
                    || ($permission
                        ->pivot
                        ->model_id == $model_id))
                && ($permission->id == $providedPermission 
                        || $permission->slug === $providedPermission)
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Attach permission to a user.
     *
     * @param int|\Bican\Roles\Models\Permission $permission
     * @param null|int|\Illuminate\Database\Eloquent\Model $entity
     * @return null|bool
     */
    public function attachPermission($permission, $entity = null)
    {
        if ($permission instanceof Permission) {
            $permission_id = $permission->id;
        } else {
            $permission_id = $permission;
        }

        if ($entity instanceof Model) {
            $model_id = $entity->id;
        } else {
            $model_id = $entity;
        }
        
        if ($this->getPermissions()->contains(function($value, $key) use ($permission_id, $model_id) {
            if ($model_id) {
                return $value
                        ->pivot
                    && ($value
                        ->pivot
                        ->model_id == $model_id)
                    && ($value->id == $permission_id);    
            }
            
            if ($value
                    ->pivot 
                && $value
                    ->pivot
                    ->model_id) {
                return false;
            }

            return $value->id == $permission_id;
        })) {
            return true;
        } else {
            return $this
                ->userPermissions()
                ->attach($permission, ['model_id' => $model_id]);
        }
    }

    /**
     * Detach permission from a user.
     *
     * @param int|\Bican\Roles\Models\Permission $permission
     * @param null|int|\Illuminate\Database\Eloquent\Model $entity
     * @return int
     */
    public function detachPermission($permission, $entity = null)
    {
        if ($entity instanceof Model) {
            $model_id = $entity->id;
        } else {
            $model_id = $entity;
        }

        $this->permissions = null;

        return $this
            ->userPermissions()
            ->wherePivot('model_id', $model_id)
            ->detach($permission);
    }

    /**
     * Detach all permissions from a user.
     *
     * @return int
     */
    public function detachAllPermissions()
    {
        $this->permissions = null;
        
        return $this->userPermissions()->detach();
    }

    /**
     * Check if pretend option is enabled.
     *
     * @return bool
     */
    private function isPretendEnabled()
    {
        return (bool) config('roles.pretend.enabled');
    }

    /**
     * Allows to pretend or simulate package behavior.
     *
     * @param string $option
     * @return bool
     */
    private function pretend($option)
    {
        return (bool) config('roles.pretend.options.' . $option);
    }

    /**
     * Get method name.
     *
     * @param string $methodName
     * @param bool $all
     * @return string
     */
    private function getMethodName($methodName, $all)
    {
        return ((bool) $all) ? $methodName . 'All' : $methodName . 'One';
    }

    /**
     * Get an array from argument.
     *
     * @param int|string|array $argument
     * @return array
     */
    private function getArrayFrom($argument)
    {
        return (!is_array($argument)) ? preg_split('/ ?[,|] ?/', $argument) : $argument;
    }

    /**
     * Handle dynamic method calls.
     *
     * @param string $method
     * @param array $parameters
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        if (starts_with($method, 'is')) {
            return $this->is(snake_case(substr($method, 2), config('roles.separator')));
        } elseif (starts_with($method, 'may')) {
            return $this->may(snake_case(substr($method, 3), config('roles.separator')));
        } elseif (starts_with($method, 'allowed')) {
            return $this->allowed(snake_case(substr($method, 7), config('roles.separator')), $parameters[0]);
        }

        return parent::__call($method, $parameters);
    }
}
