package com.hydrospark.hydrospark.repositories;


import com.hydrospark.hydrospark.entities.Hydrospark;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface HydrosparkRepo extends JpaRepository<Hydrospark,Integer> {

    @Query("select h from Hydrospark h where h.name=?1")
    List<Hydrospark> findByName(String name);
}
