package com.navjeet.auth;

import com.navjeet.auth.config.AppConstants;
import com.navjeet.auth.entities.Role;
import com.navjeet.auth.repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.UUID;


@SpringBootApplication
public class AuthAppApplication implements CommandLineRunner {

	@Autowired
	private RoleRepository roleRepository;


	static void main(String[] args) {
		SpringApplication.run(AuthAppApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		roleRepository.findByName("ROLE_"+AppConstants.ADMIN_ROLE).ifPresentOrElse(_ -> {}, () -> {
			Role role = new Role();
				role.setName("ROLE_"+AppConstants.ADMIN_ROLE);
				role.setId(UUID.randomUUID());
				roleRepository.save(role);
		});
		roleRepository.findByName("ROLE_"+AppConstants.USER_ROLE).ifPresentOrElse(_ -> {}, () -> {
			Role role = new Role();
			role.setName("ROLE_"+AppConstants.USER_ROLE);
			role.setId(UUID.randomUUID());
			roleRepository.save(role);
		});
	}

}
