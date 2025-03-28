package com.hydrospark.hydrospark.entities;


import jakarta.persistence.*;

@Entity
public class SubProducts {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int subProdId;
    private String subTypeName;
    private double subTypePrice;
    private String description;
    @Lob
    private byte[] subProdImg;
    @ManyToOne(cascade = CascadeType.ALL)
    private Product product;

    public SubProducts(String subTypeName, double subTypePrice, String description, Product product,byte[] subProdImg) {
        this.subTypeName = subTypeName;
        this.subTypePrice = subTypePrice;
        this.description = description;
        this.product = product;
        this.subProdImg=subProdImg;
    }

    public SubProducts() {
    }

    public int getSubProdId() {
        return subProdId;
    }

    public void setSubProdId(int subProdId) {
        this.subProdId = subProdId;
    }

    public String getSubTypeName() {
        return subTypeName;
    }

    public void setSubTypeName(String subTypeName) {
        this.subTypeName = subTypeName;
    }

    public double getSubTypePrice() {
        return subTypePrice;
    }

    public void setSubTypePrice(double subTypePrice) {
        this.subTypePrice = subTypePrice;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Product getProduct() {
        return product;
    }

    public void setProduct(Product product) {
        this.product = product;
    }

    public byte[] getSubProdImg() {
        return subProdImg;
    }

    public void setSubProdImg(byte[] subProdImg) {
        this.subProdImg = subProdImg;
    }
}
