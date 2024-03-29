package com.hassanemamane.springsecurity.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data @AllArgsConstructor @NoArgsConstructor
@Entity
public class UserInfo {
    // L'identifiant du client dans la base de données
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    // Le prénom
    String firstName;
    // Le nom
    String lastName;
    // L'email
    String email;
    // L'username
    String name;
    // Le mot de passe
    String password;
    // La date de naissance
    LocalDate dateOfBirth;
    // Les roles
    private String roles;
}
