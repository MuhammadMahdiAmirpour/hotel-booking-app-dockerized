package ir.ac.kntu.hotelbookingapp.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ir.ac.kntu.hotelbookingapp.model.Role;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
	Optional<Role> findByName(String name);

	boolean existsByName(String roleName);
}
