package com.hydrospark.hydrospark.repositories;

import com.hydrospark.hydrospark.entities.Employee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface EmployeeRepo extends JpaRepository<Employee,Integer> {



    @Query("select e from Employee e where e.firstName=?1 and lastName=?2")
    List<Employee> findEmployeeByFullname(String firstName,String lastName);

    @Query("select e from Employee e where e.email=?1 and e.password=?2")
    List<Employee> findEmployeeByEmailAndPassword(String email,String password);
    @Query("select e from Employee e where e.email=?1")
    List<Employee> findEmployeeByEmail(String email);

    @Query("DELETE FROM Employee e WHERE e.email = ?1")
    void deleEmployeeByEmail(String email);
}
