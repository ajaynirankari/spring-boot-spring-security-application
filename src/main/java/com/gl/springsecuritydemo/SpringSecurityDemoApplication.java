package com.gl.springsecuritydemo;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Data;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

import static org.springframework.security.config.Customizer.withDefaults;

@SpringBootApplication
public class SpringSecurityDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityDemoApplication.class, args);
    }

}

@RestController
class MyController {

    @GetMapping("/")
    public String defaultMethod() {
        return "This is default API for everyone";
    }

    @GetMapping("/home")
    public String homeMethod() {
        return "This is home API for everyone";
    }

    @GetMapping("/public/api1")
    public String apiMethod1() {
        return "This is for authenticated public API 1";
    }

    @GetMapping("/public/api2")
    public String apiMethod2() {
        return "This is for authenticated public API 2";
    }

    @GetMapping("/admin/api1")
    public String adminApiMethod1() {
        return "This is for authenticated admin API 1";
    }

    @GetMapping("/admin/api2")
    public String adminApiMethod2() {
        return "This is for authenticated admin API 2";
    }

    @PreAuthorize("hasRole('ROLE_ADMINSP')")
    @GetMapping("/private/api1")
    public String privateAdminApiMethod1() {
        return "This is for authenticated private admin API 1";
    }

    @PreAuthorize("hasRole('ROLE_ADMINSP')")
    @GetMapping("/private/api2")
    public String privateAdminApiMethod2() {
        return "This is for authenticated private admin API 2";
    }

}

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(
                request -> request
                        .requestMatchers("/", "/home").permitAll()
                        .requestMatchers("/public/**").hasRole("USER")
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
        ).formLogin(withDefaults());

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(MyUserRepo repo) {
        return (String username) -> {
            MyUser dbUser = repo.findByUsername(username);
            System.out.println("dbUser = " + dbUser);
            if (dbUser == null) {
                throw new UsernameNotFoundException("username: " + username + " not found");
            }
            UserDetails springUser = User.builder()
                    .username(dbUser.getUsername())
                    .password(dbUser.getPassword())
                    .roles(dbUser.getRoles().toArray(String[]::new))
                    .build();
            System.out.println("springUser = " + springUser);
            return springUser;
        };
/*
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("user"))
                .roles("USER").build();
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("ADMIN", "USER").build();

        return new InMemoryUserDetailsManager(user, admin);
  */

    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner loadInitialUsersInDB(MyUserRepo repo) {
        return args -> {
/*
            MyUser user1 = new MyUser();
            user1.setUsername("user");
            user1.setPassword(passwordEncoder().encode("user"));
            user1.setRoles(Set.of("USER"));
            repo.save(user1);

            MyUser user2 = new MyUser();
            user2.setUsername("admin");
            user2.setPassword(passwordEncoder().encode("admin"));
            user2.setRoles(Set.of("ADMIN", "USER"));
            repo.save(user2);

            MyUser user3 = new MyUser();
            user3.setUsername("adminsp");
            user3.setPassword(passwordEncoder().encode("adminsp"));
            user3.setRoles(Set.of("ADMINSP"));
            repo.save(user3);

            System.out.println("users save in DB");
*/
        };
    }
}

interface MyUserRepo extends JpaRepository<MyUser, Long> {
    MyUser findByUsername(String username);
}

@Data
@Entity
class MyUser {
    @Id
    @GeneratedValue
    private long id;

    @Column(unique = true)
    private String username;
    private String password;

    private Set<String> roles;
}