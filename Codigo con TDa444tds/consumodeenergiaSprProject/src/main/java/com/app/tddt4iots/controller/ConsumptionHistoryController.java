package com.app.tddt4iots.controller;

import com.app.tddt4iots.entities.ConsumptionHistory;
import com.app.tddt4iots.repository.ConsumptionHistoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/consumptionhistory")
public class ConsumptionHistoryController {

    @Autowired
    private ConsumptionHistoryRepository consumptionhistoryRepository;

    @GetMapping
    public ResponseEntity<List<ConsumptionHistory>> getConsumptionHistory() {
        List<ConsumptionHistory> listConsumptionHistory = consumptionhistoryRepository.findAll();
        return ResponseEntity.ok(listConsumptionHistory);
    }

    @PostMapping
    public ResponseEntity<ConsumptionHistory> insertConsumptionHistory(@RequestBody ConsumptionHistory consumptionhistory) {
        ConsumptionHistory newConsumptionHistory = consumptionhistoryRepository.save(consumptionhistory);
        return ResponseEntity.ok(newConsumptionHistory);
    }

    @PutMapping
    public ResponseEntity<ConsumptionHistory> updateConsumptionHistory(@RequestBody ConsumptionHistory consumptionhistory) {
        ConsumptionHistory upConsumptionHistory = consumptionhistoryRepository.save(consumptionhistory);
        if (upConsumptionHistory != null) {
            return ResponseEntity.ok(upConsumptionHistory);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping(value = "{id}")
    public ResponseEntity<ConsumptionHistory> deletePersons(@PathVariable("id") Long startDate) {
        consumptionhistoryRepository.deleteById(startDate);
        return ResponseEntity.ok(null);
    }

}
