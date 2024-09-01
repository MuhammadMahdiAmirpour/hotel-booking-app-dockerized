package ir.ac.kntu.hotelbookingapp.controller;

import ir.ac.kntu.hotelbookingapp.exception.RoleAlreadyExistException;
import ir.ac.kntu.hotelbookingapp.model.Role;
import ir.ac.kntu.hotelbookingapp.model.User;
import ir.ac.kntu.hotelbookingapp.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/roles")
@RequiredArgsConstructor
public class RoleController {
	private final RoleService roleService;

	@GetMapping("/all-roles")
	public ResponseEntity<List<Role>> getAllRoles() {
		return new ResponseEntity<>(roleService.getRoles(), HttpStatus.FOUND);
	}

	@PostMapping("/create-new-role")
	public ResponseEntity<String> createRole(@RequestBody Role theRole) {
		try {
			roleService.createRole(theRole);
			return ResponseEntity.ok("New role created successfully");
		} catch (RoleAlreadyExistException e) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
		}
	}

	@DeleteMapping("/delete/{roleId}")
	public void deleteRole(@PathVariable("roleId") Long roleId) {
		roleService.deleteRole(roleId);
	}

	@PostMapping("/remove-all-users-from-role/{roleId}")
	public Role removeAllUsersFromRole(@PathVariable("roleId") Long roleId) {
		return roleService.removeAllUsersFromRole(roleId);
	}

	@PostMapping("/remove-user-from-role")
	public User removeUserFromRole(
			@RequestParam("userId") Long userId,
			@RequestParam("roleId") Long roleId) {
		return roleService.removeUserFromRole(userId, roleId);
	}

	@PostMapping("/assign-user-to-role")
	public User assignUserToRole(
			@RequestParam("userId") Long userId,
			@RequestParam("roleId") Long roleId) {
		return roleService.assignRoleToUser(userId, roleId);
	}
}