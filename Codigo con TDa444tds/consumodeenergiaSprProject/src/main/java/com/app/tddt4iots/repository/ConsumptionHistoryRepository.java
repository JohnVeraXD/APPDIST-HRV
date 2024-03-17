package com.app.tddt4iots.repository;
 
 import com.app.tddt4iots.entities.ConsumptionHistory;
 import org.springframework.data.jpa.repository.JpaRepository;
 import java.util.*;
import java.lang.*;

 public interface ConsumptionHistoryRepository extends JpaRepository<ConsumptionHistory, Long> {
 }
