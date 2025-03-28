package com.hydrospark.hydrospark.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

import java.util.Date;

@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public int Id;

    public String firstName;

    public String lastName;

    public String email;

    public String password;

    public long number;

    public boolean visitedProduct;
    public Date dateOfProductVisit;
    public boolean contacted;

    public User() {
    }

    public User(String firstName, String lastName, String email, String password, long number) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.password = password;
        this.number = number;
    }
}
