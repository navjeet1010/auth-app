package com.navjeet.auth;

import com.navjeet.auth.entities.Role;
import com.navjeet.auth.repositories.RoleRepository;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthAppApplicationTests {

	@Test
	void applicationClassIsInstantiable() {
		new AuthAppApplication();
	}

	@Test
	void runCreatesDefaultRolesWhenMissing() throws Exception {
		RoleRepository roleRepository = mock(RoleRepository.class);
		AuthAppApplication application = new AuthAppApplication();
		ReflectionTestUtils.setField(application, "roleRepository", roleRepository);

		when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.empty());
		when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.empty());

		application.run();

		verify(roleRepository).save(argThat(role -> "ROLE_ADMIN".equals(role.getName()) && role.getId() != null));
		verify(roleRepository).save(argThat(role -> "ROLE_USER".equals(role.getName()) && role.getId() != null));
	}

	@Test
	void runDoesNotCreateRolesWhenTheyAlreadyExist() throws Exception {
		RoleRepository roleRepository = mock(RoleRepository.class);
		AuthAppApplication application = new AuthAppApplication();
		ReflectionTestUtils.setField(application, "roleRepository", roleRepository);

		when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.of(Role.builder().name("ROLE_ADMIN").build()));
		when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(Role.builder().name("ROLE_USER").build()));

		application.run();

		verify(roleRepository, never()).save(argThat(role -> true));
	}
}
