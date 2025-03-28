package com.hydrospark.hydrospark.repositories;

import com.hydrospark.hydrospark.entities.SubProducts;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SubProdRepo extends JpaRepository<SubProducts,Integer> {


    @Query("select s from SubProducts s where s.subTypeName=?1")
    List<SubProducts> findSubProductByName(String name);
    @Query("select s from SubProducts s")
    List<SubProducts> getAll();

//
    @Query("DELETE from SubProducts s where s.product.proId=?1")
    void deleteAllSubProductByProdId(int prodId);


}
