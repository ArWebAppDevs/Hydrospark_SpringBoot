package com.hydrospark.hydrospark.repositories;

import com.hydrospark.hydrospark.entities.Product;
import com.hydrospark.hydrospark.entities.SubProducts;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ProductRepo extends JpaRepository<Product,Integer> {

    @Query("select p from Product p where p.proId=?1")
    Product findById(int id);

    @Query("select p from Product p")
    List<Product> findAll();

    @Query("select p from Product p where p.productName=?1")
    Product findByName(String name);

    @Query("select p.subProducts from Product p where p.productName=?1")
    List<SubProducts> findSubProduct(String name);

//    @Query("DELETE from Product p where p.proId=?1")
//    void deleteProductById(int id);

}
