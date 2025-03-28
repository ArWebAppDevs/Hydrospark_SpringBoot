package com.hydrospark.hydrospark.entities;


import jakarta.persistence.*;

@Entity
public class Hydrospark {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String name;

    @Lob
    private byte[] img;

    public Hydrospark(String name, byte[] img) {
        this.name = name;
        this.img = img;
    }

    public Hydrospark() {
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public byte[] getImg() {
        return img;
    }

    public void setImg(byte[] img) {
        this.img = img;
    }
}
