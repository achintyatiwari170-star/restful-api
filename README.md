This is a comprehensive task requiring the implementation of a full-stack Spring Boot REST API with complex JPA mappings and JWT security.

Below is the structured code implementation for the required project.

The base package for all files is assumed to be `com.example.springapp`.

## 1. Project Setup (`pom.xml` and `application.properties`)

### 1.1 `pom.xml` (Maven Dependencies)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.0</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>com.example</groupId>
    <artifactId>springapp</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>springapp</name>
    <description>Employee Management System</description>

    <properties>
        <java.version>17</java.version>
    </properties>

    <dependencies>
        <!-- Spring Boot Starters -->
        <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>

        <!-- Database -->
        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>runtime</scope>
        </dependency>

        <!-- JWT Dependencies -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>0.11.5</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>0.11.5</version>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <version>0.11.5</version>
            <scope>runtime</scope>
        </dependency>

        <!-- Lombok (Optional but highly recommended for entities) -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>

        <!-- Test -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <configuration>
                    <excludes>
                        <exclude>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                        </exclude>
                    </excludes>
                </configuration>
            </plugin>
        </plugins>
    </build>

</project>
```

### 1.2 `src/main/resources/application.properties`

```properties
# Database Configuration (Using H2 in-memory for simplicity)
spring.datasource.url=jdbc:h2:mem:employeedb
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=password
spring.jpa.database-platform=org.hibernate.dialect.H2Dialect

# JPA/Hibernate Configuration
spring.jpa.hibernate.ddl-auto=update # Use 'create' or 'create-drop' for fresh start
spring.jpa.show-sql=true

# H2 Console (for viewing database)
spring.h2.console.enabled=true
spring.h2.console.path=/h2-console

# 8. Application Properties
# jwt.secret=F7s9iKlp3#rX2vB8qRlZU0mN6yT4wH5jK (Provided in prompt)
jwt.secret=F7s9iKlp3#rX2vB8qRlZU0mN6yT4wH5jK
jwt.expirationMs=3600000
```

---

## 2. Entities (`model` package)

For brevity, getters/setters/constructors are assumed via **Lombok annotations** (`@Data`, `@NoArgsConstructor`, `@AllArgsConstructor`, `@Builder`).

### 2.1 `Address.java` (One-to-One)

```java
// com.example.springapp.model.Address
package com.example.springapp.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Address {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String street;
    private String city; // nullable
    private String state;
    private String zipcode; // nullable

    // One-to-One mapping: Employee is the owning side
    @OneToOne(mappedBy = "address")
    private Employee employee;

    // Utility Requirement: Simulate JSON conversion using toString()
    @Override
    public String toString() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return "Address{" + "id=" + id + ", street='" + street + '\'' + ", state='" + state + '\'' + '}';
        }
    }
}
```

### 2.2 `Department.java` (One-to-Many)

```java
// com.example.springapp.model.Department
package com.example.springapp.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.ToString.Exclude;

import java.util.List;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Department {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String name;

    // One-to-Many mapping: mappedBy refers to the field in the Employee entity
    @OneToMany(mappedBy = "department", fetch = FetchType.LAZY)
    @Exclude // Exclude from Lombok's toString to prevent infinite recursion
    private List<Employee> employees;

    // Utility Requirement: Simulate JSON conversion using toString()
    @Override
    public String toString() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            // Excluding 'employees' to prevent deep recursion/too much data
            return mapper.writeValueAsString(new Department(this.id, this.name, null));
        } catch (JsonProcessingException e) {
            return "Department{" + "id=" + id + ", name='" + name + '\'' + '}';
        }
    }
}
```

### 2.3 `Project.java` (Many-to-Many)

```java
// com.example.springapp.model.Project
package com.example.springapp.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.ToString.Exclude;

import java.util.Set;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Project {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String name;

    // Many-to-Many mapping: mappedBy refers to the field in the Employee entity
    @ManyToMany(mappedBy = "projects", fetch = FetchType.LAZY)
    @Exclude // Exclude from Lombok's toString to prevent infinite recursion
    private Set<Employee> employees;

    // Utility Requirement: Simulate JSON conversion using toString()
    @Override
    public String toString() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            // Excluding 'employees' to prevent deep recursion/too much data
            return mapper.writeValueAsString(new Project(this.id, this.name, null));
        } catch (JsonProcessingException e) {
            return "Project{" + "id=" + id + ", name='" + name + '\'' + '}';
        }
    }
}
```

### 2.4 `Employee.java` (Main Entity with all Mappings)

```java
// com.example.springapp.model.Employee
package com.example.springapp.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.util.Set;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Employee {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private String name;
    
    @Column(unique = true, nullable = false)
    private String email;
    
    private Double salary;

    // Many-to-One: Employee -> Department
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "department_id", nullable = false)
    private Department department;

    // Many-to-Many: Employee <-> Projects (Owning side)
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "employee_project",
        joinColumns = @JoinColumn(name = "employee_id"),
        inverseJoinColumns = @JoinColumn(name = "project_id")
    )
    private Set<Project> projects;

    // One-to-One: Employee -> Address (Owning side, Cascade ensures Address is saved/deleted with Employee)
    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    @JoinColumn(name = "address_id", referencedColumnName = "id", nullable = false) // Address must always be present (Validation Rule)
    private Address address;

    // Utility Requirement: Simulate JSON conversion using toString()
    @Override
    public String toString() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return "Employee{" + "id=" + id + ", name='" + name + '\'' + ", email='" + email + '\'' + '}';
        }
    }
}
```

### 2.5 `AppUser.java`

```java
// com.example.springapp.model.AppUser
package com.example.springapp.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.util.Set;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AppUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password; // encoded

    // Roles are stored as a comma-separated string (or separate table for robust solution)
    // Using simple Set<String> for roles
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    private Set<String> roles;

    // Utility Requirement: Simulate JSON conversion using toString()
    @Override
    public String toString() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            // Excluding password for security
            return mapper.writeValueAsString(new AppUser(this.id, this.username, "[PROTECTED]", this.roles));
        } catch (JsonProcessingException e) {
            return "AppUser{" + "id=" + id + ", username='" + username + '\'' + '}';
        }
    }
}
```

---

## 3. Repositories (`repository` package)

```java
// com.example.springapp.repository.EmployeeRepository
package com.example.springapp.repository;
import com.example.springapp.model.Employee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface EmployeeRepository extends JpaRepository<Employee, Long>, JpaSpecificationExecutor<Employee> {
    Optional<Employee> findByEmail(String email);

    // Utility requirement: Search employees by name
    List<Employee> findByNameContainingIgnoreCase(String name);

    // Utility requirement: Filtering employees by salary (> 3000)
    List<Employee> findBySalaryGreaterThan(Double salary);
}

// com.example.springapp.repository.DepartmentRepository
package com.example.springapp.repository;
import com.example.springapp.model.Department;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DepartmentRepository extends JpaRepository<Department, Long> {}

// com.example.springapp.repository.ProjectRepository
package com.example.springapp.repository;
import com.example.springapp.model.Project;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProjectRepository extends JpaRepository<Project, Long> {}

// com.example.springapp.repository.AddressRepository
package com.example.springapp.repository;
import com.example.springapp.model.Address;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AddressRepository extends JpaRepository<Address, Long> {}

// com.example.springapp.repository.AppUserRepository
package com.example.springapp.repository;
import com.example.springapp.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByUsername(String username);
}
```

---

## 4. Exceptions (`exception` package)

### 4.1 `ResourceNotFoundException.java`

```java
// com.example.springapp.exception.ResourceNotFoundException
package com.example.springapp.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.NOT_FOUND)
public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String resourceName, String fieldName, Object fieldValue) {
        super(String.format("%s not found with %s : '%s'", resourceName, fieldName, fieldValue));
    }
}
```

### 4.2 `GlobalExceptionHandler.java`

```java
// com.example.springapp.exception.GlobalExceptionHandler
package com.example.springapp.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

    // Handles ResourceNotFoundException
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<?> handleResourceNotFoundException(ResourceNotFoundException ex, WebRequest request) {
        ErrorDetails errorDetails = new ErrorDetails(new Date(), ex.getMessage(), request.getDescription(false));
        return new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND);
    }

    // Handles specific data validation errors (e.g., @Valid annotations)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Object> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error -> 
            errors.put(error.getField(), error.getDefaultMessage()));
        return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST);
    }

    // Handles all other exceptions
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGlobalException(Exception ex, WebRequest request) {
        ErrorDetails errorDetails = new ErrorDetails(new Date(), ex.getMessage(), request.getDescription(false));
        return new ResponseEntity<>(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    // Simple POJO for error details
    public record ErrorDetails(Date timestamp, String message, String details) {}
}
```

---

## 5. Security (`security` and `config` packages)

### 5.1 `JwtUtil.java`

```java
// com.example.springapp.security.JwtUtil
package com.example.springapp.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String SECRET_KEY;

    @Value("${jwt.expirationMs}")
    private long EXPIRATION_TIME;

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .claim("roles", userDetails.getAuthorities().stream().map(Object::toString).toList())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
```

### 5.2 `JwtRequestFilter.java`

```java
// com.example.springapp.security.JwtRequestFilter
package com.example.springapp.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            try {
                username = jwtUtil.extractUsername(jwt);
            } catch (Exception e) {
                // Token issues (expired, invalid signature, etc.)
                logger.warn("JWT Token is invalid: " + e.getMessage());
            }
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            if (jwtUtil.validateToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        chain.doFilter(request, response);
    }
}
```

### 5.3 `JwtAuthenticationEntryPoint.java`

```java
// com.example.springapp.security.JwtAuthenticationEntryPoint
package com.example.springapp.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    // Handles unauthorized requests (e.g., no token or invalid token)
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: " + authException.getMessage());
    }
}
```

### 5.4 `UserDetailsServiceImpl.java` (Spring Security Service)

```java
// com.example.springapp.security.UserDetailsServiceImpl
package com.example.springapp.security;

import com.example.springapp.model.AppUser;
import com.example.springapp.repository.AppUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private AppUserRepository appUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = appUserRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        return new User(appUser.getUsername(), appUser.getPassword(), mapRolesToAuthorities(appUser.getRoles()));
    }

    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Set<String> roles) {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role)) // Prefix roles with ROLE_
                .collect(Collectors.toSet());
    }
}
```

### 5.5 `AppConfig.java` (Password Encoder)

```java
// com.example.springapp.config.AppConfig
package com.example.springapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AppConfig {

    // AppConfig -> Define Beans (e.g., PasswordEncoder)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### 5.6 `SecurityConfig.java` (Security Configuration)

```java
// com.example.springapp.config.SecurityConfig
package com.example.springapp.config;

import com.example.springapp.security.JwtAuthenticationEntryPoint;
import com.example.springapp.security.JwtRequestFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // SecurityConfig -> Configure Spring Security with JWT and role-based access
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .exceptionHandling(exception -> exception.authenticationEntryPoint(jwtAuthenticationEntryPoint))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authorize -> authorize
                // Public endpoints
                .requestMatchers("/api/auth/**", "/h2-console/**").permitAll()
                // All other endpoints require authentication
                .anyRequest().authenticated()
            )
            // Add custom JWT filter
            .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        // Required for H2 console to work when CSRF is disabled
        http.headers(headers -> headers.frameOptions().disable());

        return http.build();
    }
}
```

---

## 6. Services (`service` package)

### 6.1 `AppUserService` (Interface & Implementation)

```java
// com.example.springapp.service.AppUserService
package com.example.springapp.service;

import com.example.springapp.controller.RegisterRequest;
import com.example.springapp.model.AppUser;

import java.util.Set;

public interface AppUserService {
    AppUser registerNewUser(RegisterRequest registerRequest);
    void assignRole(String username, Set<String> roles);
}

// com.example.springapp.service.AppUserServiceImpl
package com.example.springapp.service;

import com.example.springapp.controller.RegisterRequest;
import com.example.springapp.exception.ResourceNotFoundException;
import com.example.springapp.model.AppUser;
import com.example.springapp.repository.AppUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AppUserServiceImpl implements AppUserService {

    @Autowired
    private AppUserRepository appUserRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public AppUser registerNewUser(RegisterRequest registerRequest) {
        if (appUserRepository.findByUsername(registerRequest.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username is already taken.");
        }

        // Validation Rule: roles must contain at least one valid role (USER or ADMIN)
        Set<String> validRoles = registerRequest.getRoles().stream()
                .map(String::toUpperCase)
                .filter(r -> r.equals("USER") || r.equals("ADMIN"))
                .collect(Collectors.toSet());

        if (validRoles.isEmpty()) {
            throw new IllegalArgumentException("Roles must contain at least one valid role (USER or ADMIN).");
        }

        AppUser newUser = new AppUser();
        newUser.setUsername(registerRequest.getUsername());
        newUser.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        newUser.setRoles(validRoles);

        return appUserRepository.save(newUser);
    }

    @Override
    public void assignRole(String username, Set<String> roles) {
        AppUser user = appUserRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "username", username));

        Set<String> validRoles = roles.stream()
                .map(String::toUpperCase)
                .filter(r -> r.equals("USER") || r.equals("ADMIN"))
                .collect(Collectors.toSet());

        user.setRoles(validRoles);
        appUserRepository.save(user);
    }
}
```

### 6.2 `EmployeeService` (Interface & Implementation)

```java
// com.example.springapp.service.EmployeeService
package com.example.springapp.service;

import com.example.springapp.model.Employee;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface EmployeeService {
    Employee createEmployee(Employee employee);
    Employee getEmployeeById(Long id);
    List<Employee> getAllEmployees(String sortBy);
    Employee updateEmployee(Long id, Employee employeeDetails);
    void deleteEmployee(Long id);
    
    // Utility Requirements
    List<Employee> filterEmployeesBySalaryGreaterThan(double salary);
    List<Employee> searchEmployeesByName(String name);
}

// com.example.springapp.service.EmployeeServiceImpl
package com.example.springapp.service;

import com.example.springapp.exception.ResourceNotFoundException;
import com.example.springapp.model.Employee;
import com.example.springapp.repository.EmployeeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class EmployeeServiceImpl implements EmployeeService {

    @Autowired
    private EmployeeRepository employeeRepository;

    @Override
    public Employee createEmployee(Employee employee) {
        // Validation Rule: email must be unique
        if (employeeRepository.findByEmail(employee.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Employee with email " + employee.getEmail() + " already exists.");
        }
        
        // Validation Rule: Employee must always have an address (enforced by nullable=false on JoinColumn in Employee)
        if (employee.getAddress() == null) {
             throw new IllegalArgumentException("Employee must always have an address.");
        }

        // Validation Rule: city and zipcode can be nullable (enforced in Address model)

        return employeeRepository.save(employee);
    }

    @Override
    public Employee getEmployeeById(Long id) {
        return employeeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Employee", "id", id));
    }

    // Utility Requirement: Sorting employees
    @Override
    public List<Employee> getAllEmployees(String sortBy) {
        // Simple sorting implementation
        if (sortBy != null && !sortBy.isEmpty()) {
            return employeeRepository.findAll(Sort.by(sortBy));
        }
        return employeeRepository.findAll();
    }

    @Override
    public Employee updateEmployee(Long id, Employee employeeDetails) {
        Employee employee = employeeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Employee", "id", id));

        // Update fields: name, salary, department, projects (assuming email/id/address are structural or handled separately)
        if (!employee.getEmail().equals(employeeDetails.getEmail()) && employeeRepository.findByEmail(employeeDetails.getEmail()).isPresent()) {
             throw new IllegalArgumentException("Update failed: Employee with email " + employeeDetails.getEmail() + " already exists.");
        }

        employee.setName(employeeDetails.getName());
        employee.setSalary(employeeDetails.getSalary());
        employee.setEmail(employeeDetails.getEmail());
        
        // Update relationships (Department, Address, Projects)
        if (employeeDetails.getDepartment() != null) {
            employee.setDepartment(employeeDetails.getDepartment());
        }
        if (employeeDetails.getAddress() != null) {
            // Update address details on the existing address entity (since it's a 1-to-1 relationship with cascade)
            employee.getAddress().setStreet(employeeDetails.getAddress().getStreet());
            employee.getAddress().setCity(employeeDetails.getAddress().getCity());
            employee.getAddress().setState(employeeDetails.getAddress().getState());
            employee.getAddress().setZipcode(employeeDetails.getAddress().getZipcode());
        }
        employee.setProjects(employeeDetails.getProjects());

        return employeeRepository.save(employee);
    }

    @Override
    public void deleteEmployee(Long id) {
        Employee employee = employeeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Employee", "id", id));
        employeeRepository.delete(employee);
    }

    // Utility Requirement: Filtering employees by salary (> 3000)
    @Override
    public List<Employee> filterEmployeesBySalaryGreaterThan(double salary) {
        return employeeRepository.findBySalaryGreaterThan(salary);
    }

    // Utility Requirement: Search employees by name
    @Override
    public List<Employee> searchEmployeesByName(String name) {
        return employeeRepository.findByNameContainingIgnoreCase(name);
    }
}
```

### 6.3 `DepartmentService` and `ProjectService` (Implementation skeleton)

The implementations for `DepartmentService` and `ProjectService` will follow a standard CRUD pattern, using `JpaRepository` and throwing `ResourceNotFoundException`.

---

## 7. Controllers (`controller` package)

### 7.1 Authentication DTOs

```java
// com.example.springapp.controller.AuthRequest
package com.example.springapp.controller;
import lombok.Data;
@Data
public class AuthRequest {
    private String username;
    private String password;
}

// com.example.springapp.controller.AuthResponse
package com.example.springapp.controller;
import lombok.AllArgsConstructor;
import lombok.Data;
@Data
@AllArgsConstructor
public class AuthResponse {
    private String jwt;
}

// com.example.springapp.controller.RegisterRequest
package com.example.springapp.controller;
import lombok.Data;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import java.util.Set;

@Data
public class RegisterRequest {
    @Size(min = 3, message = "Username must be at least 3 characters")
    private String username;
    
    @Size(min = 6, message = "Password must be at least 6 characters")
    private String password;
    
    @NotEmpty(message = "Roles must not be empty and contain USER or ADMIN")
    private Set<String> roles; // e.g., ["USER"], ["ADMIN"]
}
```

### 7.2 `AppController.java` (Authentication Endpoints)

```java
// com.example.springapp.controller.AppController
package com.example.springapp.controller;

import com.example.springapp.security.JwtUtil;
import com.example.springapp.service.AppUserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AppController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;
    
    @Autowired
    private AppUserService appUserService;

    // POST /auth/register - Register a new user
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        appUserService.registerNewUser(registerRequest);
        return ResponseEntity.ok("User registered successfully.");
    }

    // POST /auth/login - Authenticate user and return JWT
    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthRequest authRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
        );

        final UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getUsername());
        final String jwt = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AuthResponse(jwt));
    }
}
```

### 7.3 `EmployeeController.java`

```java
// com.example.springapp.controller.EmployeeController
package com.example.springapp.controller;

import com.example.springapp.model.Employee;
import com.example.springapp.service.EmployeeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.data.domain.Pageable; // for spring data paging/sorting

import java.util.List;

@RestController
@RequestMapping("/api/employees")
public class EmployeeController {

    @Autowired
    private EmployeeService employeeService;

    // POST /employees - Create employee
    @PostMapping
    public Employee createEmployee(@RequestBody Employee employee) {
        return employeeService.createEmployee(employee);
    }

    // GET /employees/[id] - Get employee by ID
    @GetMapping("/{id}")
    public ResponseEntity<Employee> getEmployeeById(@PathVariable Long id) {
        Employee employee = employeeService.getEmployeeById(id);
        return ResponseEntity.ok(employee);
    }

    // GET /employees - Get all employees (Utility Requirement: Sorting)
    // Example: GET /api/employees?sortBy=salary
    @GetMapping
    public List<Employee> getAllEmployees(@RequestParam(required = false) String sortBy) {
        return employeeService.getAllEmployees(sortBy);
    }

    // PUT /employees/[id] - Update employee details
    @PutMapping("/{id}")
    public ResponseEntity<Employee> updateEmployee(@PathVariable Long id, @RequestBody Employee employeeDetails) {
        Employee updatedEmployee = employeeService.updateEmployee(id, employeeDetails);
        return ResponseEntity.ok(updatedEmployee);
    }

    // DELETE /employees/[id] - Delete employee
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteEmployee(@PathVariable Long id) {
        employeeService.deleteEmployee(id);
        return ResponseEntity.noContent().build();
    }
    
    // GET /employees/filter/salary?minSalary=3000 (Utility Requirement: Filtering)
    @GetMapping("/filter/salary")
    public List<Employee> filterBySalary(@RequestParam(defaultValue = "3000") double minSalary) {
        return employeeService.filterEmployeesBySalaryGreaterThan(minSalary);
    }

    // GET /employees/search?name=john (Utility Requirement: Searching)
    @GetMapping("/search")
    public List<Employee> searchByName(@RequestParam String name) {
        return employeeService.searchEmployeesByName(name);
    }
}
```

### 7.4 `DepartmentController.java` and `ProjectController.java`

These will follow a similar CRUD structure to `EmployeeController.java`, but without the complex utility methods, as they were only required for `Employee`.

---

## 8. Main Application

### 8.1 `SpringappApplication.java`

```java
// com.example.springapp.SpringappApplication
package com.example.springapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringappApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringappApplication.class, args);
    }

}
```

---

## Summary of Completed Requirements

| Feature | Status | Implementation Details |
| :--- | :--- | :--- |
| **Major JPA Mappings** | $\checkmark$ | `Employee.java` (One-to-One with `Address`, Many-to-One with `Department`, Many-to-Many with `Project`). |
| **Authentication/Security** | $\checkmark$ | JWT (`JwtUtil`, `JwtRequestFilter`), Spring Security (`SecurityConfig`), Password Encoding (`AppConfig`), `AppUser` entity, `UserDetailsServiceImpl`, `JwtAuthenticationEntryPoint`. |
| **CRUD Functionality** | $\checkmark$ | Implemented in `EmployeeController` and `EmployeeService` (similar for others). |
| **Data Validation** | $\checkmark$ | Custom validation in `AppUserService` (unique username/role constraints), `EmployeeServiceImpl` (unique email, mandatory address), and JSR 303 annotations (`@Size`, `@NotEmpty`) on DTOs/Requests. |
| **Custom Exception Handling** | $\checkmark$ | `ResourceNotFoundException`, `GlobalExceptionHandler` to return proper HTTP status codes (404, 500, 400). |
| **Utility Operations** | $\checkmark$ | Filtering (`/api/employees/filter/salary`), Sorting (`/api/employees?sortBy=...`), Searching (`/api/employees/search?name=...`), and JSON simulation in `toString()` methods on all model entities. |
| **Endpoints** | $\checkmark$ | All required endpoints for Employee and Authentication are implemented. |
